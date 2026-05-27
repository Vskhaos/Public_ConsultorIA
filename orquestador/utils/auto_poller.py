"""
auto_poller.py — Polling de la API pública (api.laconsultoria.cat) para
auto-programar engagements creados desde el formulario público.

Arquitectura (opcion B): el orchestrator NO se expone al exterior. En su lugar,
hace polling cada POLL_INTERVAL_MIN minutos al endpoint /api/admin/events del
audit-api, autenticándose via /api/admin/login. Por cada evento futuro que
todavía no esté programado en APScheduler, llama a schedule_engagement.

Variables de entorno:
  AUDIT_API_URL          URL base, default https://api.laconsultoria.cat
  AUDIT_API_USER         usuario admin, default auditor
  AUDIT_API_PASS         password admin (se debe definir en .env)
  AUTO_POLL_INTERVAL_MIN intervalo en minutos, default 5
  AUTO_POLL_ENABLED      "true" para activar; default "false" (opt-in)
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

import httpx
from urllib.parse import urlparse

from . import scheduler as sched

logger = logging.getLogger(__name__)

API_URL  = os.getenv("AUDIT_API_URL", "https://api.laconsultoria.cat").rstrip("/")
API_USER = os.getenv("AUDIT_API_USER", "auditor")
API_PASS = os.getenv("AUDIT_API_PASS", "")
INTERVAL = int(os.getenv("AUTO_POLL_INTERVAL_MIN", "5"))
ENABLED  = os.getenv("AUTO_POLL_ENABLED", "false").lower() == "true"

# Token compartido con el API (INTERNAL_AUTH_TOKEN). Permite bypassar el captcha
# Turnstile cuando el orchestrator llama al admin_login (somos un cliente interno
# legítimo, no podemos resolver captchas).
INTERNAL_AUTH = os.getenv("INTERNAL_AUTH_TOKEN", "")

# El formulario admin guarda schedule "HH:MM-HH:MM" en hora local (sin TZ).
# Asumimos Europe/Madrid por defecto; override con AUDIT_LOCAL_TZ.
LOCAL_TZ = ZoneInfo(os.getenv("AUDIT_LOCAL_TZ", "Europe/Madrid"))

# Si api.laconsultoria.cat tiene basicauth de Traefik (caso actual), enviamos
# las credenciales como Basic Auth además del JWT en /admin/*.
BASIC_USER = os.getenv("AUDIT_API_BASIC_USER", API_USER)
BASIC_PASS = os.getenv("AUDIT_API_BASIC_PASS", API_PASS)

# Tipo por defecto cuando el evento no trae scope conocido.
DEFAULT_TIPO = os.getenv("AUDIT_DEFAULT_TIPO", "pentesting_externo")
DEFAULT_DURATION_MIN = int(os.getenv("AUDIT_DEFAULT_DURATION_MIN", "120"))

# Mapeo scope (form) → clave plantilla (phases/plantillas.py).
SCOPE_TO_TIPO = {
    "pentest_ext": "pentesting_externo",
    "pentest_int": "pentesting_interno",
    "web_app":     "auditoria_web",
    "cloud":       "cloud",
    "compliance":  "cumplimiento_normativo",
    "gdpr":        "rgpd_ens",
    "phishing":    "phishing",
    "wifi":        "red_inalambrica",
}


def _map_tipo(scope: list[str] | None) -> str:
    """Primer scope conocido gana; si no hay match, DEFAULT_TIPO."""
    for s in scope or []:
        if s in SCOPE_TO_TIPO:
            return SCOPE_TO_TIPO[s]
    return DEFAULT_TIPO


def _extraer_host(dominio_raw: str) -> str:
    """De 'https://foo.com/bar' o 'http://foo.com:8080' devuelve 'foo.com'.
    Si ya viene sin esquema (p.ej. 'foo.com'), lo devuelve tal cual.
    Esto es crítico: WhiteRabbit (Qwen-Coder 7B) copia literalmente la cadena
    objetivo a comandos como nmap, que NO acepta esquemas URL.
    """
    if not dominio_raw:
        return ""
    if "://" in dominio_raw:
        try:
            host = urlparse(dominio_raw).hostname
            if host:
                return host
        except Exception:
            pass
    # Sin esquema: quitar path y puerto si los hay
    return dominio_raw.split("/")[0].split(":")[0]


def _build_objetivo(ev: dict[str, Any], ext: dict[str, Any]) -> str:
    """Devuelve el objetivo limpio (hostname o 1ª IP) que WhiteRabbit
    copiará tal cual a comandos como nmap. Las IPs adicionales viajan
    aparte por `scope_extra` para que aplicar_scope las añada a iptables.
    """
    dominio = _extraer_host((ext.get("dominio") or "").strip())
    ips = [ip for ip in (ext.get("ips") or []) if ip]
    if dominio:
        return dominio
    if ips:
        return ips[0]
    return f"Auditoría de {ev.get('title', 'cliente')}"


def _build_scope_extra(ext: dict[str, Any]) -> list[str]:
    """IPs adicionales del scope (no incluidas en `objetivo`) que deben
    permitirse en iptables. Retorna lista vacía si no hay."""
    ips = [ip for ip in (ext.get("ips") or []) if ip]
    dominio = _extraer_host((ext.get("dominio") or "").strip())
    # Si dominio es la primera IP (porque no había hostname), evitar duplicarla
    if not dominio and ips:
        return ips[1:]
    return ips


async def _login(client: httpx.AsyncClient) -> Optional[str]:
    """Login admin → JWT. Devuelve el access_token o None si falla.

    Envía X-Internal-Auth (si está configurado) para bypassar el captcha
    Turnstile del lado API — somos un cliente interno, no humano.
    """
    headers = {}
    if INTERNAL_AUTH:
        headers["X-Internal-Auth"] = INTERNAL_AUTH
    try:
        r = await client.post(
            f"{API_URL}/api/admin/login",
            json={"username": API_USER, "password": API_PASS},
            headers=headers,
            timeout=15,
        )
        if r.status_code != 200:
            logger.warning("auto_poller: login admin → %d (internal_auth=%s)",
                           r.status_code, "set" if INTERNAL_AUTH else "missing")
            return None
        return r.json().get("access_token")
    except Exception as exc:
        logger.warning("auto_poller: login admin error: %s", exc)
        return None


def _parse_hhmm(s: str) -> tuple[int, int]:
    """Parsea 'HH:MM' o 'HH:MM:SS' → (hh, mm). Ignora segundos si vienen."""
    parts = s.strip().split(":")
    if len(parts) < 2:
        raise ValueError(f"formato horario inválido {s!r}: se requiere HH:MM")
    return int(parts[0]), int(parts[1])


def _parse_event_start(ev: dict[str, Any]) -> Optional[datetime]:
    """Combina event.start + extendedProps.schedule (HH:MM-HH:MM) en datetime UTC.

    - Si event.start trae ISO con TZ ("...+02:00" o "...Z"), se respeta.
    - Si event.start es YYYY-MM-DD (caso del form admin), se asume LOCAL_TZ
      (Europe/Madrid por defecto) tanto en la fecha como en el HH:MM del schedule.
    - Si no hay schedule, se usa medianoche local.
    """
    start_str = ev.get("start")
    if not start_str:
        return None
    sched_str = (ev.get("extendedProps") or {}).get("schedule") or ""
    hh, mm = 0, 0
    if "-" in sched_str:
        first = sched_str.split("-", 1)[0].strip()
        try:
            hh, mm = _parse_hhmm(first)
        except Exception as exc:
            logger.warning(
                "auto_poller: schedule inválido %r (ref=%s): %s — defaulting a 00:00 local",
                sched_str, ev.get("ref") or ev.get("id"), exc,
            )
    try:
        if "T" in start_str:
            dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=LOCAL_TZ)
            # si schedule existe, sobrescribe la hora respetando la TZ original
            if "-" in sched_str:
                dt = dt.replace(hour=hh, minute=mm, second=0, microsecond=0)
        else:
            y, m, d = [int(x) for x in start_str.split("-")]
            dt = datetime(y, m, d, hh, mm, tzinfo=LOCAL_TZ)
    except Exception as exc:
        logger.warning("auto_poller: fecha inválida %r: %s", start_str, exc)
        return None
    return dt.astimezone(timezone.utc)


def _duration_minutes(ev: dict[str, Any]) -> int:
    """Calcula la duración en minutos. Prioridad:
    1) extendedProps.schedule "HH:MM-HH:MM" → diferencia (ventana real del cliente).
    2) extendedProps.duration "Xd" / "X-Yd" / "Xh" → conversión.
    3) DEFAULT_DURATION_MIN.
    """
    import re
    ext = ev.get("extendedProps") or {}

    # 1) ventana HH:MM-HH:MM
    sched_str = str(ext.get("schedule") or "").strip()
    if "-" in sched_str:
        a, b = [s.strip() for s in sched_str.split("-", 1)]
        try:
            ah, am = _parse_hhmm(a)
            bh, bm = _parse_hhmm(b)
            minutes = (bh * 60 + bm) - (ah * 60 + am)
            if minutes > 0:
                return minutes
        except Exception as exc:
            logger.warning(
                "auto_poller: duración por schedule no parseable %r: %s — usando fallback",
                sched_str, exc,
            )

    # 2) duration tipo "1d", "2-3d", "8h"
    dur = str(ext.get("duration") or "").strip()
    m = re.match(r"^\s*(\d+)\s*-\s*(\d+)\s*([dhm]?)\s*$", dur)
    if m:
        n = (int(m.group(1)) + int(m.group(2))) // 2
        unit = m.group(3) or "d"
        return n * (1440 if unit == "d" else 60 if unit == "h" else 1)
    m = re.match(r"^\s*(\d+)\s*([dhm]?)\s*$", dur)
    if m:
        n = int(m.group(1))
        unit = m.group(2) or "d"
        return n * (1440 if unit == "d" else 60 if unit == "h" else 1)

    return DEFAULT_DURATION_MIN


def _build_datos_inline(ev: dict[str, Any]) -> dict[str, Any]:
    ext = ev.get("extendedProps") or {}
    return {
        "empresa_nombre":        ev.get("title") or "(sin nombre)",
        "empresa_sector":        ext.get("sector"),
        "contacto_nombre":       None,
        "contacto_email":        ext.get("email"),
        "tipo_auditoria":        _map_tipo(ext.get("scope")),
        "objetivo":              _build_objetivo(ev, ext),
        "tiempo_contratado_min": _duration_minutes(ev),
        "notas_cliente":         ext.get("tunnel"),
    }


async def poll_once() -> dict[str, int]:
    """Una pasada de polling. Devuelve estadísticas."""
    if not API_PASS:
        logger.info("auto_poller: AUDIT_API_PASS vacío, skip")
        return {"polled": 0, "scheduled": 0, "skipped_past": 0, "errors": 1}

    auth = httpx.BasicAuth(BASIC_USER, BASIC_PASS) if BASIC_PASS else None
    async with httpx.AsyncClient(auth=auth) as client:
        token = await _login(client)
        if not token:
            return {"polled": 0, "scheduled": 0, "skipped_past": 0, "errors": 1}

        try:
            r = await client.get(
                f"{API_URL}/api/admin/events",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            r.raise_for_status()
            events = r.json()
        except Exception as exc:
            logger.warning("auto_poller: fetch /api/admin/events: %s", exc)
            return {"polled": 0, "scheduled": 0, "skipped_past": 0, "errors": 1}

    now = datetime.now(timezone.utc)
    # Job ids con formato "preload:<ref>", "start:<ref>", "cleanup:<ref>".
    # Si ya hay un "start:<ref>" agendado, no reagendamos.
    scheduled_refs = {
        j["id"].split(":", 1)[1]
        for j in sched.listar_jobs()
        if j["id"].startswith("start:")
    }
    stats = {"polled": len(events), "scheduled": 0, "skipped_past": 0, "errors": 0}

    for ev in events:
        # El ref real vive en extendedProps.ref (acceso.ref). El panel lee los
        # informes desde acceso.ref/, así que el engagement DEBE usar ese mismo
        # prefijo. Fallback a AUD-<id> solo para accesos legacy sin ref.
        ref = (ev.get("extendedProps") or {}).get("ref") or f"AUD-{ev.get('id')}"
        if ref in scheduled_refs:
            continue
        inicio_at = _parse_event_start(ev)
        if inicio_at is None:
            stats["errors"] += 1
            continue
        if inicio_at <= now + timedelta(seconds=60):
            stats["skipped_past"] += 1
            continue
        datos = _build_datos_inline(ev)
        scope_extra = _build_scope_extra(ev.get("extendedProps") or {})
        try:
            sched.schedule_engagement(
                ref=ref, inicio_at=inicio_at,
                tipo=datos["tipo_auditoria"],
                objetivo=datos["objetivo"],
                tiempo_min=datos["tiempo_contratado_min"],
                datos_inline=datos,
                scope_extra=scope_extra,
            )
            stats["scheduled"] += 1
            logger.info("auto_poller: scheduled %s @ %s", ref, inicio_at.isoformat())
        except Exception as exc:
            logger.warning("auto_poller: schedule_engagement %s: %s", ref, exc)
            stats["errors"] += 1

    return stats


def register_with_scheduler() -> None:
    """Registra el job de polling en APScheduler. Idempotente."""
    if not ENABLED:
        logger.info("auto_poller: AUTO_POLL_ENABLED=false, no se registra job")
        return
    s = sched.get_scheduler()
    s.add_job(
        poll_once,
        trigger="interval",
        minutes=INTERVAL,
        id="auto_poller_main",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc) + timedelta(seconds=10),
    )
    logger.info(
        "auto_poller: registrado interval=%dmin, primer run en 10s, target=%s",
        INTERVAL, API_URL,
    )
