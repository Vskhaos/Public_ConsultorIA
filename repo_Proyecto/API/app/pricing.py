"""
pricing.py — Cálculo de precios para auditorías + integración BTCPay.

Modelo:
    precio_eur = rate_base * horas * mult_tipo_max * mult_prioridad

donde mult_tipo_max es el multiplicador del tipo más caro entre los seleccionados
(es decir, si el cliente pide externo+RGPD, manda RGPD).
"""
from __future__ import annotations

import logging
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


# Multiplicadores por tipo de auditoría
MULT_TIPO: dict[str, float] = {
    "pentest_ext": 1.0,    # baseline
    "pentest_int": 1.3,    # VPN cliente, riesgo operativo
    "web_app":     1.1,    # scope acotado
    "cloud":       1.4,    # skill especializado
    "compliance":  1.5,    # informe legal
    "gdpr":        1.5,    # idem
    "phishing":    1.2,    # infraestructura adicional
    "wifi":        1.0,
}

# Multiplicadores por prioridad (urgencia de entrega)
MULT_PRIO: dict[str, float] = {
    "low":    1.0,
    "medium": 1.3,
    "high":   1.6,
}

# Mapeo duración del select → minutos. Conservador (1h por defecto si desconocido).
DURATION_MIN: dict[str, int] = {
    "1h":   60,
    "45m":  45,
    "90m":  90,
    "2h":   120,
    "4h":   240,
    "8h":   480,
    "1d":   480,
    "2-3d": 1200,    # 2.5 días * 8h
    "1w":   2400,    # 5 días * 8h
    "2w":   4800,
    "1m":   9600,    # 20 días * 8h
}


def _duration_to_minutes(duration: str | None, fallback: int = 480) -> int:
    if not duration:
        return fallback
    if duration in DURATION_MIN:
        return DURATION_MIN[duration]
    # Formato "custom_<N>h" generado por el frontend cuando el usuario
    # selecciona "Personalizada" + introduce un número de horas.
    if duration.startswith("custom_") and duration.endswith("h"):
        try:
            horas = int(duration[len("custom_"):-1])
            if 1 <= horas <= 1000:
                return horas * 60
        except ValueError:
            pass
    return fallback


def calcular_precio(
    *,
    scope: list[str],
    duration: str | None,
    priority: str | None = "low",
    tier: str = "standard",          # 'standard' | 'enterprise'
) -> dict[str, Any]:
    """Devuelve dict con desglose:
        importe_eur (Decimal), importe_eur_cents (int),
        rate_eur_hour, horas, mult_tipo, mult_prio, tier
    """
    rate = (settings.rate_enterprise_eur_hour
            if tier == "enterprise" else settings.rate_base_eur_hour)
    minutos = _duration_to_minutes(duration)
    horas = minutos / 60.0
    mult_tipo = max((MULT_TIPO.get(s, 1.0) for s in (scope or [])), default=1.0)
    mult_prio = MULT_PRIO.get(priority or "low", 1.0)

    importe = Decimal(str(rate * horas * mult_tipo * mult_prio)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP)
    cents = int(importe * 100)
    return {
        "importe_eur":       float(importe),
        "importe_eur_cents": cents,
        "rate_eur_hour":     rate,
        "horas":             horas,
        "mult_tipo":         mult_tipo,
        "mult_prio":         mult_prio,
        "tier":              tier,
    }


# ── BTCPay client (REST API v1) ──────────────────────────────────────────────

class BTCPayError(Exception):
    pass


async def crear_invoice_btcpay(
    *,
    importe_eur_cents: int,
    audit_ref: str,
    user_email: str,
    metadata: dict | None = None,
) -> dict[str, Any]:
    """Crea una invoice en BTCPay y devuelve {id, checkoutLink, status}.

    Lanza BTCPayError si la API key, store_id o el server no están bien
    configurados — el llamador debe gestionarlo (404 vs 503).
    """
    if not settings.btcpay_api_key or not settings.btcpay_store_id:
        raise BTCPayError("BTCPay no configurado (falta API key o store_id)")

    importe_eur = importe_eur_cents / 100.0
    url = (f"{settings.btcpay_url.rstrip('/')}"
           f"/api/v1/stores/{settings.btcpay_store_id}/invoices")
    headers = {
        "Authorization": f"token {settings.btcpay_api_key}",
        "Content-Type":  "application/json",
    }
    body = {
        "amount":   f"{importe_eur:.2f}",
        "currency": "EUR",
        "metadata": {
            "buyerEmail":       user_email,
            "orderId":          audit_ref,
            "itemDesc":         f"Auditoría {audit_ref}",
            "audit_ref":        audit_ref,
            **(metadata or {}),
        },
        "checkout": {
            "redirectURL":           f"https://app.laconsultoria.cat/?paid={audit_ref}",
            "redirectAutomatically": True,
            "speedPolicy":           "MediumSpeed",
        },
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise BTCPayError(f"BTCPay no accesible: {exc}") from exc
        if r.status_code >= 400:
            raise BTCPayError(f"BTCPay {r.status_code}: {r.text[:200]}")
        return r.json()


def verify_btcpay_webhook_signature(
    payload: bytes, signature_header: str | None,
) -> bool:
    """Valida HMAC-SHA256 de la cabecera 'BTCPay-Sig: sha256=...'.
    En BTCPay el secreto del webhook se configura en el dashboard."""
    import hashlib
    import hmac

    if not settings.btcpay_webhook_secret:
        # Si no hay secret configurado, rechazamos siempre (fail-closed)
        return False
    if not signature_header:
        return False
    sig = signature_header.strip()
    if sig.startswith("sha256="):
        sig = sig[len("sha256="):]
    expected = hmac.new(
        settings.btcpay_webhook_secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig)
