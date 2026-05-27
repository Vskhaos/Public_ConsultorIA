"""Two-stage reporting con Qwen3-14B-AWQ a partir de la evidencia REAL del bucle ReAct.

Qwen3 recibe los comandos ejecutados + sus outputs reales (no hallazgos
inventados) y genera dos informes:

  1) Informe TECNICO: por fase, lista comandos -> output -> analisis ->
     vulnerabilidad si aplica -> CVE/CWE -> severidad.
  2) Informe EJECUTIVO: resumen no-tecnico para el cliente con visibilidad
     del estado de seguridad y recomendaciones priorizadas.

Evita meter toda la evidencia en un unico prompt (max_model_len=16384):
trabaja fase a fase y luego sintetiza el ejecutivo a partir del tecnico.
"""

import logging
from datetime import datetime

from utils.model_client import ask_whiterabbit

logger = logging.getLogger(__name__)

MAX_EVIDENCIA_POR_FASE = 4500  # chars de evidencia que pasamos a DeepSeek por fase

SYSTEM_TECNICO = """Eres un consultor de pentesting senior redactando un informe profesional en CASTELLANO.
Recibes evidencia REAL (comandos + outputs) de una fase y produces SOLO el contenido del apartado de esa fase. NO incluyas el titulo de la fase (ya se anade fuera). NO uses ingles. NO envuelvas la respuesta en bloques de codigo (no uses ```).

Para cada comando relevante, escribe un bloque corto:
- **Comando:** `<comando exacto>`
- **Salida resumida:** <2-3 frases>
- **Analisis:** <que indica el resultado, max 2 frases>
- **Hallazgo:** <vulnerabilidad si la hay + CVE/CWE si conoces, o "sin hallazgos relevantes">
- **Severidad:** critica | alta | media | baja | informativa

REGLAS de clasificacion de severidad (criticas para no engañar al cliente):
1. Si returncode != 0 por error DEL COMANDO mismo (opcion invalida, ruta no
   existe, archivo no encontrado, "command not found", "Unknown option") → es
   un error operativo del pentest, NO un hallazgo de seguridad del cliente.
   - Severidad: informativa
   - Hallazgo: "sin hallazgos relevantes (error operativo de herramienta)"
   - Salida resumida: redacta lo que reveló (si algo) pero NO clasifiques el
     fallo como vulnerabilidad. Si el comando es totalmente irrelevante (4
     reintentos del mismo error), OMITELO del informe en lugar de listarlo.
2. Si el comando tuvo exito (rc=0) pero NO encontro nada explotable → Severidad
   informativa, Hallazgo "sin hallazgos relevantes".
3. Severidad media/alta/critica SOLO si hay evidencia objetiva de vulnerabilidad
   en el output (banner vulnerable, CVE detectado por nuclei, SQL error visible,
   fichero sensible accesible, credenciales hardcodeadas, etc).

Maximo 6 comandos por fase. Total max 350 palabras. NO razones en voz alta, escribe directo."""

SYSTEM_EJECUTIVO = """Eres un consultor de pentesting comunicando con la direccion del cliente (perfil NO tecnico). Escribes en CASTELLANO.
Recibes un informe tecnico y produces el resumen ejecutivo. NO uses ingles, NO razones en voz alta, escribe directo. NO envuelvas la respuesta en bloques de codigo.

Estructura exacta (usa estos titulos h2):
## Postura general de seguridad
<1 parrafo, 3-4 frases sobre el estado global>

## Riesgos principales para el negocio
- <riesgo 1, sin jerga, con impacto en lenguaje de negocio>
- <riesgo 2>
- <riesgo 3 a 5 maximo>

## Recomendaciones priorizadas
1. <accion mas urgente>
2. <segunda accion>
3. <tercera accion>

Maximo 350 palabras totales. NO uses 'CVE', 'CSRF', 'XSS' — traduce a impacto de negocio."""


def _truncar_evidencia(evidencia: list[str], limite: int = MAX_EVIDENCIA_POR_FASE) -> str:
    bloque = "\n\n".join(evidencia)
    if len(bloque) <= limite:
        return bloque
    cabeza = limite // 2
    cola = limite - cabeza - 80
    return f"{bloque[:cabeza]}\n\n[... evidencia truncada ...]\n\n{bloque[-cola:]}"


async def _analizar_fase(nombre_fase: str, evidencia: list[str]) -> str:
    if not evidencia:
        return f"### {nombre_fase}\n\n_(sin evidencia capturada en esta fase)_\n"

    prompt = (
        f"Fase: {nombre_fase}\n\n"
        f"Evidencia capturada:\n{_truncar_evidencia(evidencia)}\n\n"
        f"Produce el apartado tecnico de esta fase."
    )
    try:
        cuerpo = await ask_whiterabbit(prompt, SYSTEM_TECNICO)
    except Exception as e:
        logger.warning("Qwen3 fallo analizando fase %s: %s", nombre_fase, e)
        # Fallback: pegar evidencia cruda con una nota
        cuerpo = (
            "_Qwen3 no pudo analizar esta fase, evidencia cruda incluida_\n\n"
            f"```\n{_truncar_evidencia(evidencia, limite=2000)}\n```"
        )
    return f"### {nombre_fase}\n\n{cuerpo}\n"


async def generar_informe_tecnico(
    tipo: str,
    objetivo: str,
    tiempo_usado_min: float,
    tiempo_total_min: int,
    fases_orden: list[str],
    evidencia_por_fase: dict,
    dossier: dict | None = None,
) -> str:
    """Genera el informe tecnico fase a fase con DeepSeek."""
    secciones = []
    for nombre_fase in fases_orden:
        evidencia = evidencia_por_fase.get(nombre_fase, [])
        secciones.append(await _analizar_fase(nombre_fase, evidencia))

    cuerpo_fases = "\n".join(secciones)
    contexto_dossier = ""
    if dossier and dossier.get("texto_destilado"):
        contexto_dossier = f"\n## Contexto del Engagement\n\n{dossier['texto_destilado']}\n"

    return f"""# Informe Tecnico — {tipo.replace("_", " ").title()}

## Datos del Engagement

| Campo | Valor |
|---|---|
| Objetivo | {objetivo} |
| Tipo | {tipo} |
| Duracion | {tiempo_usado_min:.0f} de {tiempo_total_min} min contratados |
| Fecha | {datetime.now().strftime("%Y-%m-%d %H:%M")} |
{contexto_dossier}
## Hallazgos por Fase

{cuerpo_fases}

---
*Informe tecnico generado automaticamente. Comandos y outputs son reales,
ejecutados durante el engagement. Analisis y clasificacion de severidad por
Qwen3-14B-AWQ.*
"""


async def generar_informe_ejecutivo(
    tipo: str,
    objetivo: str,
    informe_tecnico: str,
) -> str:
    """Sintetiza el ejecutivo a partir del tecnico (no de la evidencia cruda)."""
    # Pasamos solo las primeras N chars del tecnico para no salirnos del contexto
    resumen_input = informe_tecnico[:5000]
    prompt = (
        f"Tipo de auditoria: {tipo}\n"
        f"Objetivo: {objetivo}\n\n"
        f"Informe tecnico (extracto):\n{resumen_input}\n\n"
        f"Produce el resumen ejecutivo."
    )
    try:
        cuerpo = await ask_whiterabbit(prompt, SYSTEM_EJECUTIVO)
    except Exception as e:
        logger.warning("Qwen3 fallo generando ejecutivo: %s", e)
        cuerpo = (
            "_Qwen3 no pudo generar el resumen ejecutivo automaticamente._\n\n"
            "Por favor, revise el informe tecnico adjunto."
        )

    return f"""# Resumen Ejecutivo — Auditoria de Seguridad

| Campo | Valor |
|---|---|
| Tipo | {tipo.replace("_", " ").title()} |
| Objetivo | {objetivo} |
| Fecha | {datetime.now().strftime("%Y-%m-%d")} |

{cuerpo}

---
*Para detalle tecnico, ver informe complementario.*
"""
