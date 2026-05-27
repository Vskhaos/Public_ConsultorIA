"""
Preload de contexto para un engagement.

Responsabilidad:
  - Recopila datos crudos del cliente (de MinIO + datos inline del backend).
  - Llama a DeepSeek para DESTILARLOS en un dossier sintético.
  - Guarda el dossier en Redis (TTL 30 min) listo para la fase de ejecucion.
  - Hace una request "warmup" a WhiteRabbit con el system prompt enriquecido
    para que vLLM precalcule el KV-cache (prefix caching) — la primera
    respuesta real durante el engagement sera mas rapida.

Aislamiento de credenciales (requisito del proyecto):
  - SOLO este modulo (corriendo dentro del orquestador) toca MinIO/backend.
  - WhiteRabbit recibe unicamente el dossier ya destilado, NUNCA datos crudos
    ni credenciales. Las configs WG/SSH del cliente se referencian en el
    dossier como "disponibles" pero no se incluyen en el prompt.
"""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import urllib3
from dotenv import load_dotenv
from minio import Minio
from minio.error import S3Error

# Defensivo: server.py ya carga .env via load_dotenv en su entrypoint, pero
# scripts/tests ad-hoc que importan utils.intel sin pasar por server.py se
# encontraban con MINIO_ACCESS_KEY="" → SDK firmaba como anonimo → 403.
# Cargamos aqui sin override para no pisar nada que ya este en el entorno.
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
if _ENV_PATH.exists():
    load_dotenv(_ENV_PATH, override=False)

from utils.model_client import ask_deepseek, ask_whiterabbit  # noqa: E402
from utils.state_manager import set_dossier  # noqa: E402

logger = logging.getLogger(__name__)

MINIO_HOST       = os.getenv("MINIO_HOST", "10.20.30.40:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
MINIO_BUCKET     = os.getenv("MINIO_BUCKET", "audit-files")

SYSTEM_DESTILADOR = (
    "Eres un analista de pentesting. Recibes datos crudos sobre un engagement "
    "(empresa, scope, notas del cliente) y produces un dossier tecnico breve "
    "(<= 400 palabras) que oriente al ejecutor del pentest. Estructura: "
    "1) Empresa y sector. 2) Scope tecnico. 3) Vectores prioritarios segun el "
    "tipo de auditoria. 4) Cualquier restriccion declarada por el cliente. "
    "NO incluyas claves, IPs internas ni rutas de configuracion."
)


_MINIO_CONNECT_TIMEOUT = float(os.getenv("MINIO_CONNECT_TIMEOUT", "3"))
_MINIO_READ_TIMEOUT    = float(os.getenv("MINIO_READ_TIMEOUT", "10"))


def _minio_client() -> Minio:
    # Fail-fast: si el host MinIO en isard (o la VPN) no responde, queremos
    # un fallo en ~3-13s en vez de bloquear el scheduler 13 minutos.
    http_client = urllib3.PoolManager(
        timeout=urllib3.Timeout(
            connect=_MINIO_CONNECT_TIMEOUT,
            read=_MINIO_READ_TIMEOUT,
        ),
        retries=urllib3.Retry(total=1, backoff_factor=0),
    )
    return Minio(
        MINIO_HOST,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
        http_client=http_client,
    )


def _comprobar_artefactos_cliente(ref: str) -> dict:
    """Lista que ficheros del cliente existen en MinIO sin leer su contenido.
    Si MinIO no responde (VPN caída, host inaccesible), devuelve artefactos
    vacíos sin propagar — el engagement puede seguir sin contexto opcional."""
    artefactos = {"wg_config": False, "ssh_key": False, "otros": []}
    try:
        cli = _minio_client()
        for obj in cli.list_objects(MINIO_BUCKET, prefix=f"{ref}/", recursive=True):
            nombre = obj.object_name.split("/")[-1]
            if nombre == "wg_config.conf":
                artefactos["wg_config"] = True
            elif nombre in ("ssh_key", "ssh_key.pem", "id_rsa"):
                artefactos["ssh_key"] = True
            elif nombre and not nombre.startswith("informe"):
                artefactos["otros"].append(nombre)
    except S3Error as e:
        logger.warning("No se pudo listar artefactos de %s: %s", ref, e)
    except Exception as e:
        logger.warning("MinIO inalcanzable al comprobar artefactos de %s: %s", ref, e)
    return artefactos


async def _destilar_dossier(datos_inline: dict, artefactos: dict) -> str:
    """Llama a DeepSeek para producir el dossier en lenguaje natural."""
    prompt = (
        f"Datos del engagement:\n"
        f"- Empresa: {datos_inline.get('empresa_nombre', 'desconocida')}\n"
        f"- Sector: {datos_inline.get('empresa_sector', 'no declarado')}\n"
        f"- Tipo de auditoria: {datos_inline.get('tipo_auditoria', 'no declarado')}\n"
        f"- Objetivo tecnico: {datos_inline.get('objetivo', 'no declarado')}\n"
        f"- Tiempo contratado: {datos_inline.get('tiempo_contratado_min', '?')} min\n"
        f"- Notas del cliente: {datos_inline.get('notas_cliente', 'sin notas')}\n"
        f"- Acceso WireGuard del cliente: {'disponible' if artefactos['wg_config'] else 'no entregado'}\n"
        f"- Acceso SSH del cliente: {'disponible' if artefactos['ssh_key'] else 'no entregado'}\n"
        f"\nProduce el dossier."
    )
    try:
        return await ask_deepseek(prompt, SYSTEM_DESTILADOR)
    except Exception as e:
        logger.exception("Fallo al destilar dossier con DeepSeek: %s", e)
        # Fallback minimo: dossier sintetico sin LLM, para no bloquear el engagement
        return (
            f"Empresa: {datos_inline.get('empresa_nombre','?')}. "
            f"Tipo: {datos_inline.get('tipo_auditoria','?')}. "
            f"Objetivo: {datos_inline.get('objetivo','?')}. "
            f"Tiempo: {datos_inline.get('tiempo_contratado_min','?')} min."
        )


async def _warmup_whiterabbit(dossier_texto: str, system_base: str) -> None:
    """Calienta el KV-cache de WhiteRabbit con el system prompt enriquecido.

    vLLM con --enable-prefix-caching reutilizara este prefijo cuando llegue
    la primera request real, ahorrando computo.
    """
    system_enriquecido = f"{system_base}\n\nCONTEXTO DEL ENGAGEMENT:\n{dossier_texto}"
    try:
        await ask_whiterabbit("Confirma que has recibido el contexto.", system_enriquecido)
        logger.info("Warmup de WhiteRabbit OK")
    except Exception as e:
        logger.warning("Warmup de WhiteRabbit fallo (no critico): %s", e)


async def preload_dossier(ref: str, datos_inline: dict, system_base_wr: str) -> dict:
    """Punto de entrada del preload. Devuelve el dossier guardado.

    Si el engagement requiere VPN (artefactos.wg_config==True), tambien
    levanta wg-quick y valida handshake en este momento (T-20). Asi tenemos
    20 minutos de margen para reaccionar a fallos de conectividad antes de
    la hora contratada. NO se ejecuta ningun comando contra la red del cliente
    hasta T-0 (legalidad).
    """
    logger.info("Preload iniciado para ref=%s", ref)
    artefactos = _comprobar_artefactos_cliente(ref)
    dossier_texto = await _destilar_dossier(datos_inline, artefactos)

    dossier = {
        "ref": ref,
        "generado_en": datetime.now(timezone.utc).isoformat(),
        "datos_inline": datos_inline,
        "artefactos_disponibles": artefactos,
        "texto_destilado": dossier_texto,
    }
    set_dossier(ref, dossier)
    await _warmup_whiterabbit(dossier_texto, system_base_wr)

    # Levantar VPN si el cliente aporto wg_config (importacion local para
    # evitar ciclo: vpn.py importa state_manager, y intel ya lo importa)
    if artefactos.get("wg_config"):
        from utils.vpn import levantar_wg
        logger.info("Engagement %s requiere VPN: levantando wg...", ref)
        vpn_estado = await levantar_wg(ref)
        dossier["vpn"] = vpn_estado
        # Re-guardamos con la info de VPN
        set_dossier(ref, dossier)
        if not vpn_estado.get("ok"):
            logger.error("VPN preload fallo para %s: %s", ref, vpn_estado.get("razon"))
        else:
            logger.info("VPN %s up (estado=%s)", vpn_estado["iface"], vpn_estado["estado"])
    else:
        dossier["vpn"] = {"estado": "not_required"}

    logger.info("Preload completado para ref=%s (dossier %d chars)", ref, len(dossier_texto))
    return dossier
