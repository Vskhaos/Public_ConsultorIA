"""Critic agent: revisor adversarial sobre la Action que propone el Red.

Diseñado para correr sobre el mismo backend Qwen3-14B-AWQ que el Red, pero
con system prompt distinto y vista fresca (sin historial completo). El Critic
emite uno de tres verdicts: APPROVE | ADVISE | VETO.

- VETO: la Action no se ejecuta. Motivo se inyecta al Red para que reproponga.
- ADVISE: la Action se ejecuta. La crítica se añade a la Observation.
- APPROVE: la Action se ejecuta sin nota.

Activación: env var CRITIC_ENABLED=true. Por defecto OFF (compat backward).
Frecuencia: cada CRITIC_EVERY_N iteraciones + en hitos detectados por heurística.
"""

import json
import logging
import os
import re
import time

from utils.model_client import ask_whiterabbit_chat
from utils import memory_store

logger = logging.getLogger(__name__)

# Audit trail JSON estructurado consumido por Wazuh-agent (lee stdout via journald).
# Un logger separado evita ruido en el logger principal y permite filtrar fácil en
# rsyslog/journald → wazuh rules.
audit_log = logging.getLogger("orchestrator.critic.audit")
audit_log.propagate = True  # que también vaya al root para captura por systemd

CRITIC_ENABLED = os.environ.get("CRITIC_ENABLED", "false").lower() in ("1", "true", "yes")
CRITIC_EVERY_N = int(os.environ.get("CRITIC_EVERY_N", "3"))

# Patrones de hitos que disparan al Critic aunque no toque por turno.
# Lista deliberadamente amplia: prefiero "Critic se gasta una llamada de más"
# a "ejecutamos algo peligroso sin revisar".
_HITO_PATTERNS = [
    # Destructivos
    r"\brm\s+-[rf]+",
    r"\bmkfs\b", r"\bdd\s+if=", r"\bshred\b",
    r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bpoweroff\b",
    r":\s*\(\s*\)\s*\{",  # fork bomb
    # Firewall / red propios
    r"\biptables\b", r"\bufw\b", r"\bnft\b",
    r"\bsystemctl\s+(stop|disable|mask)\b",
    # Exfiltración insegura
    r"\bcurl\s+http://(?!localhost|127\.)",
    r"\bwget\s+http://(?!localhost|127\.)",
    r"\bnc\s+-l\b",  # listener (puede ser RCE backdoor)
    # Herramientas ofensivas heavy
    r"\bsqlmap\b.*--(level|risk)\s*[3-9]",
    r"\bhydra\b",
    r"\bmsfconsole\b", r"\bmsfvenom\b", r"\bmetasploit\b",
    r"\bnmap\b.*\s-p-",  # full-port scan
    r"\bnuclei\b.*-t\s+\w+/\w+/\w+",  # paths anidados → templates pesados
    # Instalación nueva (cambia entorno)
    r"\bapt[- ]get\s+install\b", r"\bapt\s+install\b",
    r"\bpip\s+install\b", r"\bpip3\s+install\b",
    r"\bcurl\s+.*\|\s*(sh|bash)",  # curl | bash
    # Eval / exec
    r"\beval\s+", r"\bexec\s+",
]
_HITO_RE = re.compile("|".join(_HITO_PATTERNS), re.IGNORECASE)


SYSTEM_CRITIC = """Eres un pentester senior revisando la propuesta de un junior.
Tu único trabajo es decidir si el comando que propone debe ejecutarse, con qué
ajuste, o ser vetado.

Output: SOLO una línea JSON con esta forma exacta, sin markdown, sin texto extra:
{"verdict":"APPROVE","reason":"<motivo breve, max 25 palabras>"}

Valores válidos de verdict:
- APPROVE: el comando es seguro, dentro de scope, eficiente. Razón puede ser "ok".
- ADVISE: el comando se puede ejecutar, pero hay una mejora obvia (flag, timing,
  herramienta más adecuada). Reason explica la mejora en 1 frase.
- VETO: el comando NO debe ejecutarse. Solo veta por estas causas:
    1. Toca un host/IP fuera de Scope autorizado.
    2. Es destructivo en el container o el host (rm -rf /, mkfs, dd sobre disco,
       fork bomb, shutdown/reboot).
    3. Es un DoS de hecho (hydra sin -t / -W, nmap -p- sin -T4 ni --max-rate en
       targets de producción, sqlmap --level 5 --risk 3 sin justificación).
    4. Apunta al propio orchestrator, container pentest-tools, infraestructura
       interna del operador (10.2.136.0/24, IPs de los VPS).
    5. Exfiltra datos fuera por HTTP plano a hosts no-cliente.

REGLAS:
- No vetes por "podría romperse el target" si el cliente autorizó el pentest.
  Pentest es invasivo por definición.
- No vetes apt-get install salvo que apunte a un repo no oficial.
- ADVISE > VETO siempre que puedas. Veto es la última opción.
- Si la Action es "FINAL", siempre APPROVE.
- Si dudas y el comando parece estándar de recon (nmap top-1000, nuclei, ffuf
  con common.txt, curl, dig, whatweb), APPROVE.
- NO razones en voz alta. SOLO el JSON.
"""


def critic_should_run(iter_idx: int, action: str, force: bool = False) -> bool:
    """Decide si el Critic debe correr este turno.

    iter_idx: índice 0-based de la iteración actual del Red.
    action: comando propuesto por el Red.
    force: si True, ignora heurística y siempre devuelve True (debug/tests).
    """
    if not CRITIC_ENABLED:
        return False
    if force:
        return True
    if not action:
        return False
    if action.strip().upper().startswith("FINAL"):
        return False  # no merece la pena
    # Cada N iter (excepto la 0, que es la primera y todavía no hay contexto)
    if iter_idx > 0 and iter_idx % CRITIC_EVERY_N == 0:
        return True
    # Hito detectado por heurística
    if _HITO_RE.search(action):
        return True
    return False


def _construir_prompt_critic(
    fase: str,
    objetivo: str,
    scope: list[str],
    action: str,
    turnos_recientes: list[dict],
    notas_dossier: str = "",
    memoria_findings: str = "",
) -> str:
    """Vista fresca: solo lo necesario para juzgar la Action."""
    bloque_turnos = ""
    if turnos_recientes:
        partes = []
        for t in turnos_recientes[-3:]:
            partes.append(
                f"- $ {t.get('action', '?')[:120]} "
                f"→ rc={t.get('returncode', '?')}"
                f"{' (timeout)' if t.get('timeout_hit') else ''}"
            )
        bloque_turnos = "Últimos turnos del Red:\n" + "\n".join(partes) + "\n\n"
    bloque_memoria = ""
    if memoria_findings:
        bloque_memoria = memoria_findings + "\n"
    return (
        f"Fase: {fase}\n"
        f"Objetivo: {objetivo}\n"
        f"Scope autorizado: {', '.join(scope) if scope else objetivo}\n"
        f"{bloque_turnos}"
        f"{bloque_memoria}"
        f"Notas dossier (resumen): {(notas_dossier or '(sin dossier)')[:300]}\n\n"
        f"Action propuesta por el Red:\n  {action}\n\n"
        "Emite tu veredicto JSON ahora."
    )


_RE_JSON = re.compile(r"\{[^{}]*\"verdict\"[^{}]*\}", re.DOTALL)


def _parsear_verdict(texto: str) -> dict:
    """Tolerante: si el modelo se sale de formato, fallback a APPROVE para no bloquear."""
    if not texto:
        return {"verdict": "APPROVE", "reason": "critic_empty_output"}
    m = _RE_JSON.search(texto)
    candidate = m.group(0) if m else texto.strip()
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        logger.warning("Critic no devolvió JSON parseable: %r", texto[:200])
        return {"verdict": "APPROVE", "reason": "critic_parse_error"}
    verdict = str(data.get("verdict", "APPROVE")).upper().strip()
    if verdict not in ("APPROVE", "ADVISE", "VETO"):
        verdict = "APPROVE"
    reason = str(data.get("reason", "")).strip()[:200] or "ok"
    return {"verdict": verdict, "reason": reason}


def _audit_emit(
    verdict: str, reason: str, fase: str, objetivo: str,
    action: str, scope: list[str], engagement_id: str | None,
    latency_ms: int, error: str | None = None,
) -> None:
    """Emite una línea JSON al audit logger. Wazuh-agent la recoge vía journald.

    El nivel se mapea a la severidad Wazuh:
    - VETO  → WARNING (regla custom puede subirlo a level 10+ en Wazuh).
    - ADVISE → INFO (level 5).
    - APPROVE → DEBUG (level 3, normalmente no alerta).
    - error → ERROR (fail-open Critic).
    """
    evento = {
        "src": "orchestrator.critic",
        "ts": int(time.time()),
        "engagement_id": engagement_id,
        "fase": fase,
        "objetivo": objetivo,
        "scope_count": len(scope),
        "action_preview": (action or "")[:200],
        "verdict": verdict,
        "reason": reason[:300],
        "latency_ms": latency_ms,
    }
    if error:
        evento["error"] = error
    linea = "CRITIC_AUDIT " + json.dumps(evento, ensure_ascii=False, separators=(",", ":"))
    if error or verdict == "VETO":
        audit_log.warning(linea)
    elif verdict == "ADVISE":
        audit_log.info(linea)
    else:
        audit_log.debug(linea)


async def evaluar_action(
    fase: str,
    objetivo: str,
    scope: list[str],
    action: str,
    turnos_recientes: list[dict] | None = None,
    notas_dossier: str = "",
    engagement_id: str | None = None,
) -> dict:
    """Llama al Critic y devuelve {'verdict': ..., 'reason': ...}.

    Si el Critic falla (excepción, timeout, parse error), devuelve APPROVE
    para no bloquear el flujo (fail-OPEN deliberado — el Critic es una
    capa extra de seguridad, no la única).

    También emite un evento JSON estructurado al audit log que Wazuh recoge
    desde stdout via journald.
    """
    # Memory: top-2 findings similares (objetivo+fase) para que el Critic
    # tenga contexto histórico ("esto ya falla en este target", etc.).
    memoria_findings_txt = ""
    try:
        rows = await memory_store.retrieve(
            query=action[:200], fase=fase, objetivo=objetivo, top_k=2,
        )
        if rows:
            memoria_findings_txt = memory_store.format_for_prompt(
                rows, max_chars_each=250,
            )
    except Exception as e:
        logger.warning("memory.retrieve para Critic falló: %s", e)

    messages = [
        {"role": "system", "content": SYSTEM_CRITIC},
        {"role": "user", "content": _construir_prompt_critic(
            fase, objetivo, scope, action, turnos_recientes or [], notas_dossier,
            memoria_findings=memoria_findings_txt,
        )},
    ]
    t0 = time.monotonic()
    try:
        respuesta = await ask_whiterabbit_chat(messages, max_tokens=200, temperature=0.1)
    except Exception as e:
        logger.warning("Critic falló (fail-open): %s", e)
        latency = int((time.monotonic() - t0) * 1000)
        _audit_emit(
            "APPROVE", f"critic_error:{type(e).__name__}", fase, objetivo,
            action, scope, engagement_id, latency, error=str(e)[:200],
        )
        return {"verdict": "APPROVE", "reason": f"critic_error:{type(e).__name__}"}
    verdict_data = _parsear_verdict(respuesta)
    latency = int((time.monotonic() - t0) * 1000)
    _audit_emit(
        verdict_data["verdict"], verdict_data["reason"], fase, objetivo,
        action, scope, engagement_id, latency,
    )
    return verdict_data
