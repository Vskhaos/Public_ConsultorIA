import asyncio
import io
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import urllib3
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from minio import Minio
from minio.error import S3Error
from pydantic import BaseModel, Field

load_dotenv()

from orquestador import ejecutar_engagement
from tools.react_loop import SYSTEM_REACT
from utils import scheduler as sched
from utils import auto_poller
from utils import memory_store
from utils.intel import preload_dossier
from utils.state_manager import get_dossier

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

MINIO_HOST       = os.getenv("MINIO_HOST", "10.20.30.40:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
MINIO_BUCKET     = os.getenv("MINIO_BUCKET", "audit-files")
# MinIO REMOTO opcional (replica). Si MINIO_HOST_REMOTO está vacío, no se replica.
# Pensado para que los informes lleguen al MinIO de producción (VPS3) donde
# el cliente los descarga vía panel, además del MinIO local del orchestrator.
MINIO_HOST_REMOTO       = os.getenv("MINIO_HOST_REMOTO", "")
MINIO_ACCESS_KEY_REMOTO = os.getenv("MINIO_ACCESS_KEY_REMOTO", MINIO_ACCESS_KEY)
MINIO_SECRET_KEY_REMOTO = os.getenv("MINIO_SECRET_KEY_REMOTO", MINIO_SECRET_KEY)
MINIO_BUCKET_REMOTO     = os.getenv("MINIO_BUCKET_REMOTO", MINIO_BUCKET)
INFORMES_DIR     = Path(os.getenv("INFORMES_LOCAL_DIR",
                                  "/home/auditor/ai_pentest/orchestrator/informes_local"))
_MINIO_TIMEOUT   = urllib3.Timeout(
    connect=float(os.getenv("MINIO_CONNECT_TIMEOUT", "3")),
    read=float(os.getenv("MINIO_READ_TIMEOUT", "10")),
)


def _guardar_local(key: str, contenido: str) -> str:
    """Fallback: guarda el informe en disco local cuando MinIO no responde."""
    dst = INFORMES_DIR / key
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(contenido, encoding="utf-8")
    logger.info("Informe guardado en disco local: %s", dst)
    return f"local://{dst}"


def _mk_minio_client(host: str, ak: str, sk: str) -> Optional[Minio]:
    if not host:
        return None
    http_client = urllib3.PoolManager(
        timeout=_MINIO_TIMEOUT,
        retries=urllib3.Retry(total=1, backoff_factor=0),
    )
    return Minio(host, access_key=ak, secret_key=sk, secure=False, http_client=http_client)


def _put_md(cli: Minio, bucket: str, key: str, data: bytes, etiqueta: str) -> bool:
    """Sube data al cliente MinIO indicado. Devuelve True si OK, False si falla.
    No lanza — el caller decide qué hacer con el fallo."""
    try:
        if not cli.bucket_exists(bucket):
            cli.make_bucket(bucket)
        cli.put_object(bucket, key, io.BytesIO(data), len(data),
                       content_type="text/markdown")
        logger.info("Subido a MinIO[%s]: %s/%s", etiqueta, bucket, key)
        return True
    except S3Error as e:
        logger.error("MinIO[%s] S3Error en %s: %s", etiqueta, key, e)
    except Exception as e:
        logger.warning("MinIO[%s] inalcanzable en %s: %s", etiqueta, key, e)
    return False


def _subir_md(cli_local: Minio, cli_remoto: Optional[Minio], key: str, contenido: str) -> Optional[str]:
    """Dual-write: sube al MinIO local (obligatorio) y, si configurado, al remoto
    (best-effort, no bloqueante). Si el local falla, hace fallback a disco."""
    data = contenido.encode("utf-8")
    ok_local = _put_md(cli_local, MINIO_BUCKET, key, data, "local")
    if cli_remoto is not None:
        _put_md(cli_remoto, MINIO_BUCKET_REMOTO, key, data, "remoto")
    if ok_local:
        return key
    return _guardar_local(key, contenido)


def subir_informes_a_minio(ref: str, informes: dict) -> dict:
    """Sube informes tecnico y ejecutivo a MinIO local + opcionalmente al remoto.
    Si el local falla, hace fallback a disco. Devuelve dict con keys (path
    remoto o 'local://' + path absoluto) por cada informe."""
    cli_local = _mk_minio_client(MINIO_HOST, MINIO_ACCESS_KEY, MINIO_SECRET_KEY)
    cli_remoto = _mk_minio_client(MINIO_HOST_REMOTO, MINIO_ACCESS_KEY_REMOTO, MINIO_SECRET_KEY_REMOTO)
    if isinstance(informes, str):
        return {"informe": _subir_md(cli_local, cli_remoto, f"{ref}/informe.md", informes)}
    return {
        "tecnico":   _subir_md(cli_local, cli_remoto, f"{ref}/informe_tecnico.md", informes["tecnico"]),
        "ejecutivo": _subir_md(cli_local, cli_remoto, f"{ref}/informe_ejecutivo.md", informes["ejecutivo"]),
    }


# Alias retro-compat usado por scheduler._start_job
def subir_informe_a_minio(ref: str, informe) -> Optional[str]:
    keys = subir_informes_a_minio(ref, informe)
    return keys.get("tecnico") or keys.get("informe")


# Backend al que avisamos cuando un engagement termina y sube informes.
# Reutiliza el mismo token interno + basic-auth de Traefik que auto_poller.
_BACKEND_URL   = os.getenv("AUDIT_API_URL", "https://app.laconsultoria.cat").rstrip("/")
_INTERNAL_AUTH = os.getenv("INTERNAL_AUTH_TOKEN", "")
# Mismo fallback que auto_poller: basic-auth dedicado o las credenciales de API.
_BASIC_USER    = os.getenv("AUDIT_API_BASIC_USER", os.getenv("AUDIT_API_USER", ""))
_BASIC_PASS    = os.getenv("AUDIT_API_BASIC_PASS", os.getenv("AUDIT_API_PASS", ""))


def marcar_completada_backend(ref: str) -> bool:
    """Avisa al backend de que el engagement `ref` terminó y los informes ya
    están en MinIO, para que marque el Acceso como 'completada' y el panel
    muestre los botones de descarga. Best-effort: si falla, log warning y
    sigue (los informes ya están subidos; se puede re-disparar a mano).
    Devuelve True si el backend confirmó la actualización."""
    if not _INTERNAL_AUTH:
        logger.warning("marcar_completada_backend %s: INTERNAL_AUTH_TOKEN vacío, skip", ref)
        return False
    import httpx
    auth = httpx.BasicAuth(_BASIC_USER, _BASIC_PASS) if _BASIC_PASS else None
    try:
        r = httpx.post(
            f"{_BACKEND_URL}/api/admin/audits/{ref}/uploaded",
            headers={"X-Internal-Auth": _INTERNAL_AUTH},
            auth=auth,
            timeout=15,
        )
        if r.status_code == 200:
            logger.info("Backend marcó %s completada: %s", ref, r.json())
            return True
        logger.warning("marcar_completada_backend %s: HTTP %s %s",
                       ref, r.status_code, r.text[:200])
        return False
    except Exception as exc:
        logger.warning("marcar_completada_backend %s: %s", ref, exc)
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    sched.start()
    auto_poller.register_with_scheduler()
    # Memory store: init en background para no bloquear startup si pgvector tarda.
    asyncio.create_task(memory_store.init())
    yield
    sched.shutdown()
    await memory_store.close()


app = FastAPI(title="AI Pentest Orchestrator", lifespan=lifespan)


# ---- Schemas ----

class DatosInline(BaseModel):
    """Datos que el backend envia al cerrar una contratacion. El orquestador
    los usa para destilar el dossier — NO se exponen tal cual a WhiteRabbit."""
    empresa_nombre: str
    empresa_sector: Optional[str] = None
    contacto_nombre: Optional[str] = None
    contacto_email: Optional[str] = None
    tipo_auditoria: str = Field(..., description="clave de phases.plantillas")
    objetivo: str
    tiempo_contratado_min: int
    notas_cliente: Optional[str] = None


class EngagementRequest(BaseModel):
    """Compatibilidad con el endpoint sincrono original."""
    tipo: str
    objetivo: str
    tiempo_minutos: int
    ref: str


class ScheduleRequest(BaseModel):
    """Programa un engagement: preload @ inicio_at - LEAD_MIN, start @ inicio_at."""
    ref: str
    inicio_at: datetime  # ISO 8601, recomendado UTC con sufijo Z
    datos: DatosInline


class PreloadRequest(BaseModel):
    """Disparo manual del preload — para tests o reprocesado."""
    ref: str
    datos: DatosInline


# ---- Endpoints ----

@app.get("/health")
async def health():
    return {"status": "ok", "scheduler_jobs": len(sched.listar_jobs())}


@app.post("/engagement")
async def launch_engagement(req: EngagementRequest):
    """Endpoint sincrono original (compat). Ejecuta YA, sin preload."""
    try:
        informes = await ejecutar_engagement(
            tipo=req.tipo, objetivo=req.objetivo,
            tiempo_minutos=req.tiempo_minutos, ref=req.ref,
        )
        keys = subir_informes_a_minio(req.ref, informes)
        completada = marcar_completada_backend(req.ref)
        return {"ok": True, "minio_keys": keys, "completada": completada}
    except Exception as e:
        logger.exception("Error en engagement: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/schedule")
async def schedule(req: ScheduleRequest):
    """Programa un engagement: encola preload+start con APScheduler."""
    inicio_at = req.inicio_at
    if inicio_at.tzinfo is None:
        inicio_at = inicio_at.replace(tzinfo=timezone.utc)
    try:
        info = sched.schedule_engagement(
            ref=req.ref, inicio_at=inicio_at,
            tipo=req.datos.tipo_auditoria, objetivo=req.datos.objetivo,
            tiempo_min=req.datos.tiempo_contratado_min,
            datos_inline=req.datos.model_dump(),
        )
        return {"ok": True, **info}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/preload")
async def preload(req: PreloadRequest):
    """Disparo manual del preload (para tests o reprocesado)."""
    dossier = await preload_dossier(req.ref, req.datos.model_dump(), SYSTEM_REACT)
    return {"ok": True, "ref": req.ref,
            "dossier_chars": len(dossier["texto_destilado"]),
            "artefactos": dossier["artefactos_disponibles"],
            "vpn": dossier.get("vpn", {})}


@app.get("/dossier/{ref}")
async def ver_dossier(ref: str):
    """Devuelve el dossier guardado en Redis (debug)."""
    d = get_dossier(ref)
    if d is None:
        raise HTTPException(status_code=404, detail="dossier no encontrado o expirado")
    return d


@app.get("/jobs")
async def listar_jobs():
    return {"jobs": sched.listar_jobs()}


@app.delete("/schedule/{ref}")
async def cancelar(ref: str):
    return sched.cancel_engagement(ref)
