"""
descargo.py — Generación del PDF de descargo de responsabilidad y
verificación de la firma electrónica con `endesive`.

Cadena de confianza: FNMT-RCM (raíz) → AC FNMT Usuarios (intermedia) →
certificado de usuario (FNMT o Cl@ve PIN/Permanente, ambos emitidos
por la misma jerarquía).

Flujo:
  1. Cliente solicita PDF descargo  → `generar_pdf_descargo(audit_data)`.
  2. Cliente firma localmente con AutoFirma (PAdES nivel B, T o LT).
  3. Cliente sube el PDF firmado    → `validar_pdf_firmado(pdf_bytes)`.
  4. Si válido, persistimos en `DescargoFirmado` y desbloqueamos la auditoría.
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"
FNMT_ROOT_PATH = CERTS_DIR / "AC_RAIZ_FNMT-RCM_SHA256.cer"
FNMT_USUARIOS_PATH = CERTS_DIR / "AC_FNMT_Usuarios.cer"


# ─────────────────────────────────────────────────────────────────────────────
# Generación del PDF
# ─────────────────────────────────────────────────────────────────────────────

def generar_pdf_descargo(audit_data: dict) -> bytes:
    """Genera el PDF del descargo con los datos de la auditoría.
    El cliente lo descarga, lo firma con AutoFirma y lo sube de vuelta."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=f"Descargo de responsabilidad — {audit_data.get('ref', '')}",
        author="laconsultoria.cat",
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle("T", parent=styles["Heading1"],
                            alignment=TA_CENTER, fontSize=16, spaceAfter=14)
    subtitle = ParagraphStyle("S", parent=styles["Heading2"],
                               alignment=TA_CENTER, fontSize=11, spaceAfter=20,
                               textColor=colors.grey)
    body = ParagraphStyle("B", parent=styles["Normal"],
                           alignment=TA_JUSTIFY, fontSize=10, spaceAfter=8, leading=14)
    footer = ParagraphStyle("F", parent=styles["Italic"], fontSize=8,
                             alignment=TA_CENTER, textColor=colors.grey)

    el: list = []
    el.append(Paragraph("DESCARGO DE RESPONSABILIDAD", title))
    el.append(Paragraph("Autorización para auditoría de seguridad informática", subtitle))

    fecha_ini = audit_data.get("fecha_inicial", "")
    if isinstance(fecha_ini, datetime):
        fecha_ini = fecha_ini.strftime("%Y-%m-%d %H:%M")

    table_data = [
        ["Referencia", audit_data.get("ref", "—")],
        ["Empresa contratante", audit_data.get("empresa_nombre", "—")],
        ["CIF / NIF", audit_data.get("cif", "—")],
        ["Representante (firmante)", audit_data.get("representante", "—")],
        ["Fecha de inicio", str(fecha_ini) or "—"],
        ["Duración estimada", f"{audit_data.get('duration', 0)} min"],
        ["Tipo(s) de auditoría", ", ".join(audit_data.get("scope", [])) or "—"],
        ["Dominio objetivo", audit_data.get("dominio") or "—"],
        ["IPs objetivo", ", ".join(audit_data.get("ips", [])) or "—"],
    ]
    table = Table(table_data, colWidths=[5 * cm, 11 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    el.append(table)
    el.append(Spacer(1, 16))

    el.append(Paragraph(
        "El abajo firmante, en su calidad de representante de la empresa contratante, "
        "AUTORIZA expresamente a Consultoría (<b>laconsultoria.cat</b>) y a su plataforma "
        "automatizada de auditoría asistida por inteligencia artificial a realizar las "
        "pruebas de penetración, análisis de vulnerabilidades y/o auditoría de cumplimiento "
        "descritas, sobre los activos detallados en la tabla superior, durante la ventana "
        "temporal indicada.",
        body))
    el.append(Paragraph("DECLARA expresamente que:", body))
    for txt in [
        "(a) Es titular legítimo, o tiene autorización plena y verificable del titular, de los activos auditados.",
        "(b) Ha leído y acepta el alcance técnico descrito y entiende que las pruebas pueden producir interrupciones temporales del servicio.",
        "(c) Renuncia a cualquier reclamación contra Consultoría por daños derivados de la ejecución de las pruebas dentro del scope autorizado.",
        "(d) Asume la responsabilidad legal exclusiva en caso de que los activos no fueran de su titularidad o careciera de la autorización referida en (a).",
        "(e) Acepta que el informe técnico generado contendrá información sensible y se compromete a tratarlo con la diligencia debida.",
    ]:
        el.append(Paragraph(txt, body))

    el.append(Spacer(1, 18))
    el.append(Paragraph(
        f"Documento generado automáticamente el {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}. "
        f"Debe firmarse electrónicamente con certificado FNMT o Cl@ve a través de AutoFirma "
        f"(formato PAdES). Sin firma válida, la auditoría no se ejecutará.",
        footer))
    el.append(Spacer(1, 24))
    el.append(Paragraph("Firma electrónica del representante:", body))
    el.append(Spacer(1, 60))

    doc.build(el)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# Validación de la firma
# ─────────────────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _load_trusted_pems() -> tuple[bytes, ...]:
    """Carga los certs FNMT raíz e intermedio en formato PEM (cacheado)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pems: list[bytes] = []
    for path in (FNMT_ROOT_PATH, FNMT_USUARIOS_PATH):
        if not path.exists():
            raise FileNotFoundError(f"Cert FNMT no encontrado: {path}")
        cert = x509.load_der_x509_certificate(path.read_bytes())
        pems.append(cert.public_bytes(serialization.Encoding.PEM))
    return tuple(pems)


def _extract_pkcs7_blobs(pdf_bytes: bytes) -> list[bytes]:
    """Extrae los blobs PKCS#7 (CMS SignedData) embebidos en un PDF firmado.
    Localiza `/Contents <HEX...>` para cada Sig. Tolerante a espacios."""
    blobs: list[bytes] = []
    for m in re.finditer(rb"/Contents\s*<([0-9a-fA-F\s]+)>", pdf_bytes):
        raw = m.group(1)
        clean = b"".join(raw.split())
        if not clean:
            continue
        try:
            blobs.append(bytes.fromhex(clean.decode("ascii")))
        except ValueError:
            continue
    return blobs


def _extract_signer_info(pkcs7_blob: bytes) -> dict[str, Any]:
    """Saca DN del firmante, número de serie y fecha de firma del CMS."""
    from asn1crypto import cms

    info: dict[str, Any] = {"dn": "", "serial": "", "firmado_at": None}
    try:
        ci = cms.ContentInfo.load(pkcs7_blob.rstrip(b"\x00"))
        signed_data = ci["content"]
        signer_infos = signed_data["signer_infos"]
        if not signer_infos:
            return info
        si = signer_infos[0]

        sid = si["sid"]
        serial_int: int | None = None
        if sid.name == "issuer_and_serial_number":
            serial_int = sid.chosen["serial_number"].native
            info["serial"] = format(serial_int, "X")  # hex MAYÚSC

        # Cert del firmante: buscarlo en el set de certificates
        for cert_choice in signed_data["certificates"]:
            cert = cert_choice.chosen
            if cert["tbs_certificate"]["serial_number"].native == serial_int:
                info["dn"] = cert["tbs_certificate"]["subject"].human_friendly
                break

        # Fecha de firma (signing_time o signing-time-stamp)
        if "signed_attrs" in si and si["signed_attrs"]:
            for attr in si["signed_attrs"]:
                if attr["type"].native == "signing_time":
                    info["firmado_at"] = attr["values"][0].native
                    break
    except Exception as exc:
        logger.warning("No se pudo extraer signer info: %s", exc)
    return info


def validar_pdf_firmado(pdf_bytes: bytes) -> dict[str, Any]:
    """Valida la firma del PDF contra la cadena raíz FNMT.

    Devuelve dict:
      valid:        bool
      sha256:       str (siempre, del PDF subido)
      signer_dn:    str ("CN=..., O=..., C=ES") si valid
      signer_serial:str (hex)
      firmado_at:   datetime (UTC) si la firma incluye signing_time
      error:        str|None
    """
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    base = {
        "valid": False, "sha256": sha256,
        "signer_dn": "", "signer_serial": "",
        "firmado_at": None, "error": None,
    }

    try:
        trusted = list(_load_trusted_pems())
    except Exception as exc:
        base["error"] = f"trust store no disponible: {exc}"
        return base

    try:
        from endesive.pdf import verify  # type: ignore
    except ImportError as exc:
        base["error"] = f"endesive no instalado: {exc}"
        return base

    try:
        # endesive 2.18 firma:  verify(pdfdata, certs=None, systemCertsPath=None)
        # `certs` admite tanto PEM como DER; los almacenamos en PEM.
        results = verify(pdf_bytes, certs=trusted, systemCertsPath=None)
    except Exception as exc:
        base["error"] = f"verificación PAdES falló: {exc}"
        return base

    if not results:
        base["error"] = "el PDF no contiene firmas digitales"
        return base

    # endesive devuelve una lista de tuplas/listas; los 3 primeros son
    # (hashok, signatureok, certok). Aceptamos la firma si TODOS son True.
    valid_idx = -1
    diag: list[str] = []
    for i, r in enumerate(results):
        try:
            hashok, sigok, certok = bool(r[0]), bool(r[1]), bool(r[2])
        except Exception:
            diag.append(f"firma#{i+1}: forma inesperada {r!r}")
            continue
        diag.append(f"firma#{i+1}: hash={hashok} sig={sigok} cert={certok}")
        if hashok and sigok and certok:
            valid_idx = i
            break

    if valid_idx < 0:
        base["error"] = "; ".join(diag) or "ninguna firma válida"
        return base

    blobs = _extract_pkcs7_blobs(pdf_bytes)
    if valid_idx < len(blobs):
        info = _extract_signer_info(blobs[valid_idx])
        base.update(info)

    base["valid"] = True
    return base
