"""
Scheduler de engagements (preload @ T-LEAD_MIN, ejecucion @ T-0).

Usa APScheduler AsyncIOScheduler con RedisJobStore para que los jobs
sobrevivan a reinicios del orquestador (Redis ya esta corriendo en
0.0.0.0:6379, no anadimos infraestructura).

Diseno:
  - Cuando llega POST /schedule {ref, inicio_at, datos_inline}, se anaden
    DOS jobs DateTrigger:
      1. preload_job(ref, datos_inline)  @ inicio_at - LEAD_MIN
      2. start_job(ref, tipo, objetivo, tiempo_min)  @ inicio_at
  - Si el preload falla, el start sigue ejecutandose pero sin dossier
    (degradacion elegante).
  - Al ejecutarse start, lee el dossier de Redis y se lo pasa al
    orquestador.
"""
import logging
import os
from datetime import datetime, timedelta, timezone

from apscheduler.jobstores.redis import RedisJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.date import DateTrigger

logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "0.0.0.0")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB_JOBS = int(os.getenv("REDIS_DB_JOBS", "1"))  # DB 1 para jobs (DB 0 = engagements)
LEAD_MIN = int(os.getenv("PRELOAD_LEAD_MIN", "20"))
CLEANUP_MARGIN_MIN = int(os.getenv("CLEANUP_MARGIN_MIN", "5"))

_scheduler: AsyncIOScheduler | None = None


def _build_scheduler() -> AsyncIOScheduler:
    jobstore = RedisJobStore(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB_JOBS)
    sched = AsyncIOScheduler(
        jobstores={"default": jobstore},
        timezone="UTC",
    )
    return sched


def start():
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    _scheduler = _build_scheduler()
    _scheduler.start()
    logger.info("Scheduler iniciado (LEAD_MIN=%d, jobstore=Redis db=%d)",
                LEAD_MIN, REDIS_DB_JOBS)
    return _scheduler


def shutdown():
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Scheduler detenido")


def get_scheduler() -> AsyncIOScheduler:
    if _scheduler is None:
        raise RuntimeError("Scheduler no iniciado")
    return _scheduler


async def _preload_job(ref: str, datos_inline: dict):
    """Job que se ejecuta a T-LEAD_MIN. Importes diferidos para evitar
    ciclos en el arranque del modulo."""
    from utils.intel import preload_dossier
    from tools.react_loop import SYSTEM_REACT
    try:
        await preload_dossier(ref, datos_inline, SYSTEM_REACT)
    except Exception as e:
        logger.exception("Preload job ref=%s fallo: %s", ref, e)


async def _start_job(ref: str, tipo: str, objetivo: str, tiempo_min: int,
                     scope_extra: list[str] | None = None):
    """Job que se ejecuta a T-0. Lanza el engagement con el dossier que
    deberia haber dejado el preload en Redis. La limpieza fuerte (VPN,
    estado) la hace tambien `_cleanup_job` por si este crashea."""
    from orquestador import ejecutar_engagement
    from utils.state_manager import get_dossier
    from utils.vpn import bajar_wg, get_vpn_state
    from server import subir_informes_a_minio, marcar_completada_backend
    dossier = get_dossier(ref)
    if dossier is None:
        logger.warning("start ref=%s sin dossier — ejecuto sin contexto preload", ref)
    try:
        informes = await ejecutar_engagement(
            tipo=tipo, objetivo=objetivo, tiempo_minutos=tiempo_min,
            dossier=dossier, ref=ref, scope_extra=scope_extra or None,
        )
        subir_informes_a_minio(ref, informes)
        marcar_completada_backend(ref)
    except Exception as e:
        logger.exception("Start job ref=%s fallo: %s", ref, e)
    finally:
        # Cierre best-effort. Si crashea, _cleanup_job lo hace despues.
        if get_vpn_state(ref) == "ready":
            try:
                res = await bajar_wg(ref)
                logger.info("VPN bajada para ref=%s: %s", ref, res)
            except Exception as e:
                logger.warning("bajar_wg fallo en finally ref=%s: %s — cleanup_job lo intentara", ref, e)


async def _cleanup_job(ref: str):
    """Job de seguridad que se ejecuta a T-fin + CLEANUP_MARGIN_MIN.

    Garantiza que aunque _start_job haya crasheado (proceso muerto, host
    reiniciado, kill -9), la VPN se baja y el estado se libera. Idempotente:
    bajar_wg solo actua si la interfaz esta up; delete de Redis no falla si
    la clave ya no existe.
    """
    from utils.vpn import bajar_wg, get_vpn_state
    from utils.state_manager import eliminar_engagement, eliminar_dossier
    logger.info("Cleanup job ref=%s arrancando", ref)
    try:
        if get_vpn_state(ref) == "ready":
            res = await bajar_wg(ref)
            logger.info("Cleanup ref=%s: VPN bajada (%s)", ref, res)
        else:
            logger.info("Cleanup ref=%s: VPN ya estaba abajo", ref)
    except Exception as e:
        logger.exception("Cleanup ref=%s: bajar_wg fallo: %s", ref, e)
    try:
        eliminar_dossier(ref)
    except Exception as e:
        logger.warning("Cleanup ref=%s: eliminar_dossier fallo: %s", ref, e)


def schedule_engagement(ref: str, inicio_at: datetime, tipo: str, objetivo: str,
                        tiempo_min: int, datos_inline: dict,
                        scope_extra: list[str] | None = None) -> dict:
    """Encola los dos jobs (preload + start) para un engagement.

    Reglas:
      - inicio_at debe ser timezone-aware en UTC. Si esta en el pasado
        respecto a now+1min, se rechaza.
      - Si ya existian jobs para esta ref, se reemplazan (replace_existing).
    """
    sched = get_scheduler()
    now = datetime.now(timezone.utc)
    if inicio_at <= now + timedelta(seconds=30):
        raise ValueError(f"inicio_at debe ser >= now + 30s (now={now.isoformat()})")

    preload_at = inicio_at - timedelta(minutes=LEAD_MIN)
    if preload_at <= now:
        # Engagement programado a < LEAD_MIN: preload inmediato
        preload_at = now + timedelta(seconds=2)
        logger.warning("ref=%s programado a < %d min — preload sera inmediato", ref, LEAD_MIN)

    sched.add_job(
        _preload_job, trigger=DateTrigger(run_date=preload_at),
        args=[ref, datos_inline],
        id=f"preload:{ref}", replace_existing=True,
    )
    sched.add_job(
        _start_job, trigger=DateTrigger(run_date=inicio_at),
        args=[ref, tipo, objetivo, tiempo_min, scope_extra or []],
        id=f"start:{ref}", replace_existing=True,
    )
    cleanup_at = inicio_at + timedelta(minutes=tiempo_min + CLEANUP_MARGIN_MIN)
    sched.add_job(
        _cleanup_job, trigger=DateTrigger(run_date=cleanup_at),
        args=[ref],
        id=f"cleanup:{ref}", replace_existing=True,
    )
    logger.info("Engagement ref=%s programado: preload=%s, start=%s, cleanup=%s",
                ref, preload_at.isoformat(), inicio_at.isoformat(), cleanup_at.isoformat())
    return {"ref": ref, "preload_at": preload_at.isoformat(),
            "start_at": inicio_at.isoformat(),
            "cleanup_at": cleanup_at.isoformat(), "lead_min": LEAD_MIN}


def cancel_engagement(ref: str) -> dict:
    sched = get_scheduler()
    cancelados = []
    for job_id in (f"preload:{ref}", f"start:{ref}", f"cleanup:{ref}"):
        try:
            sched.remove_job(job_id)
            cancelados.append(job_id)
        except Exception:
            pass
    return {"ref": ref, "cancelados": cancelados}


def listar_jobs() -> list[dict]:
    sched = get_scheduler()
    return [
        {"id": j.id, "next_run": j.next_run_time.isoformat() if j.next_run_time else None,
         "args": list(j.args)}
        for j in sched.get_jobs()
    ]
