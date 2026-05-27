"""
captcha.py — Verificación de tokens Cloudflare Turnstile.

El token llega del front después de que el widget invisible se resuelva.
Lo validamos contra siteverify de Cloudflare antes de aceptar el signup.

Modo estricto (fail-close) por defecto:
  - Si `TURNSTILE_SECRET` no está configurado → rechaza la petición. Esto evita
    que un despliegue accidental sin la env var deje el signup abierto a bots
    (incidente detectado en la auditoría del 18/5: el endpoint creaba cuentas
    sin verificar token).
  - Si la API de Cloudflare devuelve error / timeout → rechaza la petición.
    Antes era fail-open por disponibilidad; ahora fail-close por seguridad.

Escape hatch SOLO para dev local: si `CAPTCHA_DISABLED=1` está en el entorno,
el verificador devuelve True sin más. Nunca poner esto en producción.

Además, clientes internos legítimos (auto_poller del orchestrator, otros
servicios propios que llegan vía red privada y no pueden resolver captcha)
pueden enviar el header `X-Internal-Auth: <token>`. Si matchea el valor de
`INTERNAL_AUTH_TOKEN` la verificación se considera satisfecha.
"""
import hmac
import logging
import httpx
from fastapi import Request

from .config import settings

logger = logging.getLogger("captcha")

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
INTERNAL_AUTH_HEADER = "X-Internal-Auth"


def has_valid_internal_auth(request: Request) -> bool:
    """True si la request lleva un X-Internal-Auth válido. Constant-time."""
    expected = settings.internal_auth_token
    if not expected:
        return False  # bypass deshabilitado
    provided = request.headers.get(INTERNAL_AUTH_HEADER, "")
    if not provided:
        return False
    return hmac.compare_digest(provided, expected)


async def verify_captcha_or_internal(
    request: Request, token: str | None, remote_ip: str | None = None,
) -> bool:
    """Devuelve True si la request satisface CUALQUIERA de:
      - header X-Internal-Auth válido (servicio interno).
      - token Turnstile válido (usuario humano del front).
    """
    if has_valid_internal_auth(request):
        return True
    return await verify_turnstile(token, remote_ip)


async def verify_turnstile(token: str | None, remote_ip: str | None = None) -> bool:
    """True si el token es válido. False en cualquier otro caso (fail-close).

    Bypass solo si `CAPTCHA_DISABLED=1` está explícito en el entorno (dev local).
    """
    if settings.captcha_disabled:
        logger.warning("CAPTCHA_DISABLED activo — Turnstile bypassed (NO usar en prod)")
        return True
    if not settings.turnstile_secret:
        logger.error("Turnstile NO configurado (TURNSTILE_SECRET vacío) — rechazando petición")
        return False
    if not token:
        return False
    data = {"secret": settings.turnstile_secret, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(SITEVERIFY_URL, data=data)
        if resp.status_code != 200:
            logger.warning("Turnstile siteverify HTTP %s", resp.status_code)
            return False
        body = resp.json()
        ok = bool(body.get("success"))
        if not ok:
            logger.warning("Turnstile rechazado: %s", body.get("error-codes"))
        return ok
    except Exception as exc:
        logger.error("Turnstile verify exception (fail-close): %s", exc)
        return False
