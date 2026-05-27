"""Renderizado profesional del informe a PDF.

Toma el informe en Markdown que sube el orchestrator a MinIO y produce un PDF
corporativo con portada, cabeceras/pies y tipografía profesional. La plantilla
HTML/CSS vive en app/templates/informe.html y se renderiza con WeasyPrint.

Se invoca on-the-fly cuando el cliente pide el informe en formato PDF
(parámetro `?format=pdf` en GET /api/me/audits/{ref}/informe/{tipo}). El MD se
mantiene como fuente de verdad — el PDF se regenera cada vez con la versión
actual de la plantilla, así que cualquier mejora visual se aplica
retroactivamente a informes ya generados.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import markdown
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# WeasyPrint se importa lazy: la importación inicializa GObject y carga libs de
# sistema (pango, cairo). Hacerlo en module-import bloquea el startup de la API
# si las libs no están. Si por alguna razón el container no las tiene, el
# endpoint devolverá 503 cuando intenten generar PDF, pero el resto de la API
# sigue funcionando.
_WEASY = None
def _get_weasy():
    global _WEASY
    if _WEASY is None:
        from weasyprint import HTML, CSS  # noqa: F401
        _WEASY = HTML
    return _WEASY


_TEMPLATES_DIR = Path(__file__).parent / "templates"
_jinja = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)

_TIPO_TITULO = {
    "tecnico": "Informe técnico",
    "ejecutivo": "Resumen ejecutivo",
}
_TIPO_SUBTITULO = {
    "tecnico": "Hallazgos detallados, evidencia técnica y recomendaciones",
    "ejecutivo": "Postura general de seguridad y plan de acción",
}

# Mapeo de niveles textuales a badges HTML coloreados. Se aplican post-render.
_SEVERIDADES = {
    "crítica": ("#c0392b", "#fdecea"),
    "critica": ("#c0392b", "#fdecea"),
    "alta": ("#d35400", "#fdf2e9"),
    "media": ("#b7860b", "#fef9e7"),
    "baja": ("#2a7d3a", "#eafaf1"),
    "informativa": ("#1f57a4", "#eaf2fb"),
}


def _md_a_html(md_text: str) -> str:
    """Convierte el cuerpo del informe (markdown) a HTML.

    Quitamos el título h1 del propio informe (`# Informe Técnico —`) porque la
    portada ya lleva el título; mantenerlo dos veces queda redundante en el
    PDF."""
    cuerpo = re.sub(r"^#\s+Informe.*?\n", "", md_text, count=1, flags=re.MULTILINE)
    cuerpo = re.sub(r"^#\s+Resumen.*?\n", "", cuerpo, count=1, flags=re.MULTILINE)
    html = markdown.markdown(
        cuerpo,
        extensions=["tables", "fenced_code", "sane_lists", "nl2br"],
        output_format="html5",
    )
    html = _colorear_severidades(html)
    return html


def _colorear_severidades(html: str) -> str:
    """Inserta un badge coloreado al lado de cada `Severidad: <nivel>` que
    encuentre el regex. Hace el informe técnico mucho más legible al ojear."""
    def repl(m: re.Match) -> str:
        prefijo = m.group(1)
        nivel = m.group(2).strip().lower()
        fg, bg = _SEVERIDADES.get(nivel, ("#4a5568", "#edf2f7"))
        badge = (
            f'<span style="display:inline-block;background:{bg};color:{fg};'
            f'border:1px solid {fg};padding:1px 8px;border-radius:9px;'
            f'font-size:9pt;font-weight:700;text-transform:uppercase;'
            f'letter-spacing:0.5px;">{nivel}</span>'
        )
        return f"{prefijo}{badge}"
    return re.sub(
        r"(<strong>Severidad:?\s*</strong>:?\s*)([A-Za-záéíóúñÁÉÍÓÚÑ]+)",
        repl,
        html,
    )


def _extraer_objetivo_del_md(md_text: str, fallback: str = "—") -> str:
    """Busca el campo `Objetivo` dentro de la tabla `Datos del Engagement`."""
    m = re.search(r"\|\s*Objetivo\s*\|\s*([^|]+?)\s*\|", md_text)
    if m:
        return m.group(1).strip()
    return fallback


def render_informe_pdf(
    *,
    md_text: str,
    ref: str,
    tipo: str,
    empresa_nombre: str,
    fecha_emision: Optional[datetime] = None,
    marca: str = "ConsultorIA",
    equipo: str = "Equipo de auditoría — ConsultorIA",
    version_doc: str = "1.0",
) -> bytes:
    """Renderiza el PDF profesional a partir del Markdown del informe."""
    HTML = _get_weasy()
    fecha_emision = fecha_emision or datetime.utcnow()
    tipo_titulo = _TIPO_TITULO.get(tipo, "Informe")
    subtitulo = _TIPO_SUBTITULO.get(tipo, "")
    objetivo = _extraer_objetivo_del_md(md_text)

    titulo = "Informe de Auditoría de Seguridad"
    if tipo == "ejecutivo":
        titulo = "Resumen Ejecutivo de Auditoría"

    cuerpo_html = _md_a_html(md_text)

    plantilla = _jinja.get_template("informe.html")
    html = plantilla.render(
        marca=marca.upper(),
        titulo=titulo,
        subtitulo=subtitulo,
        tipo_titulo=tipo_titulo,
        tipo_audit=tipo.replace("_", " ").title(),
        cliente=empresa_nombre or "—",
        objetivo=objetivo,
        ref=ref,
        fecha_emision=fecha_emision.strftime("%d/%m/%Y"),
        equipo=equipo,
        version_doc=version_doc,
        cuerpo=cuerpo_html,
    )

    pdf_bytes = HTML(string=html).write_pdf()
    logger.info("PDF informe generado ref=%s tipo=%s size=%d", ref, tipo, len(pdf_bytes))
    return pdf_bytes
