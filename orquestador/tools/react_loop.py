"""Bucle ReAct (Thought/Action/Observation) sobre WhiteRabbit.

WhiteRabbit razona qué herramienta lanzar, devuelve el comando, el orquestador
lo ejecuta en el container pentest-tools, captura la salida y se la devuelve
como Observation. Itera hasta que el modelo responde Action: FINAL o se agota
el presupuesto de iteraciones.

NO es tool calling estructurado: usamos parsing de texto plano. Es mas portable
entre LLMs y mas facil de debuggear leyendo el log.
"""

import logging
import re

from utils.model_client import ask_whiterabbit_chat
from utils import memory_store
from .runner import ejecutar_comando
from .critic import critic_should_run, evaluar_action, CRITIC_ENABLED

logger = logging.getLogger(__name__)

MAX_OBSERVATION_CHARS = 1500  # con max_model_len=4096 hay margen, pero historial crece
RE_THOUGHT = re.compile(r"Thought:\s*(.+?)(?=\n\s*Action:|$)", re.DOTALL | re.IGNORECASE)
RE_ACTION  = re.compile(r"Action:\s*(.+?)(?=\n\s*(?:Thought:|Observation:)|$)", re.DOTALL | re.IGNORECASE)

SYSTEM_REACT = """Eres un pentester ofensivo trabajando en una auditoria autorizada.
Operas dentro de un container Kali con egress filtrado al scope autorizado del cliente.
Si intentas tocar IPs fuera de scope, el firewall del container bloqueara el trafico (no es un error tuyo).

Para cada paso, responde EXACTAMENTE en este formato (sin marcado markdown):

Thought: <razonamiento breve, max 2 frases>
Action: <UN solo comando bash a ejecutar>

Si has agotado los pasos utiles o tienes evidencia suficiente, responde:
Thought: <conclusion>
Action: FINAL

REGLAS DE SCOPE (CRITICO):
- USA EXCLUSIVAMENTE los hostnames y las IPs que aparecen en "Scope autorizado".
- PROHIBIDO usar IPs RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), 127.0.0.1
  ni ejemplos genericos de tu entrenamiento, EXCEPTO si la IP esta explicitamente
  en "Scope autorizado". Si una IP/red privada figura en scope, usala libremente.
- Si una Observation indica timeout, "Connection refused", returncode!=0 contra una
  IP fuera de scope: NO repitas. PIVOTA a otro target del scope o a otra tecnica.
- Si el firewall te bloquea una IP, es porque NO esta autorizada. No insistas.
- Si comprometes una maquina y desde ella enumeras una red interna, los hosts
  descubiertos cuentan como scope efectivo solo si el cliente los lista, o si el
  briefing autoriza explicitamente "pivoting hacia red interna alcanzada".

Reglas operativas:
- Un solo comando por Action. Sin pipes encadenando >5 binarios.
- Si te falta una herramienta, instala con: apt-get install -y <pkg>
- Tras tu Action recibiras Observation: con stdout/stderr/returncode reales.
- Cada comando tiene un timeout duro de ~180s. Si lo superas no obtienes salida.

GESTION DEL TIEMPO (proporcional al budget de la fase):
El prompt de usuario te dice cuanto tiempo tienes para esta fase. Ajusta el alcance:
- Budget chico (< 5 min): tecnicas rapidas. Ej. nmap top-100 (-T4 --top-ports 100),
  nuclei con templates ligeros, curl + whatweb. NUNCA `nmap -p-` ni wordlists grandes
  ni hydra contra usuarios validos.
- Budget medio (5-30 min): puedes ampliar a top-1000, ffuf con `common.txt`, nikto
  completo, nuclei full. Sigue evitando `-p-` salvo que el target sea critico.
- Budget grande (> 30 min): si justifica el hallazgo puedes lanzar `nmap -p- -T4`,
  ffuf con `big.txt`, sqlmap con `--level 3 --risk 2`, hydra con listas razonables.
- En cualquier caso usa flags acotados (-T4, --max-time, --timeout, -maxtime) y
  PRIORIZA hallazgos rapidos antes de lanzar barridos exhaustivos.

Herramientas pre-instaladas (lista no exhaustiva):
- OSINT pasivo: subfinder, amass, theHarvester, dig, whois, dnsenum, dnsrecon, host, jq
- Recon/scan: nmap, whatweb, masscan, sslscan, wafw00f, nc, curl
  (OJO: el binario `httpx` de este container es el CLIENTE HTTP de Python, NO el httpx de ProjectDiscovery. NO sirve para recon: no tiene -title/-tech-detect/-status-code/-threads. Para fingerprint/probing usa `whatweb`.)
- Web: nikto, nuclei, ffuf, gobuster, wpscan, sqlmap, wapiti
- Proxy/escaner web: zaproxy en headless es lento de arrancar (>20s) y suele dar
  TIMEOUT con timeout_por_comando=180s. PREFIERE mitmdump o usa nuclei + ffuf en
  lugar de zaproxy. Si insistes con zap: `zaproxy -daemon -port 8090 -config
  api.disablekey=true` y deja correr en background con `&`.
- Auth/passwords: hydra
- Burp Suite Community ES GUI — en este entorno NO hay display. NO uses burpsuite,
  usa zaproxy headless (con cuidado por el timeout) o mitmdump.
- Eres libre de apt-get install cualquier otra herramienta que necesites.

Rutas REALES en el container (NO inventes paths):
- nuclei-templates: /usr/share/nuclei-templates/  (ya clonadas, NO hagas git clone)
  * SIEMPRE pasar `-t` explicito Y un subdirectorio acotado, nunca http/ completo
    (tiene 10k+ templates → timeout asegurado con budget de fase de 3-6 min).
  * Comando rapido recomendado (~30-60s): `nuclei -u https://TARGET -t /usr/share/nuclei-templates/http/exposed-panels/ -severity medium,high,critical -timeout 5 -no-color -silent`
  * Otros subdirs utiles y acotados:
    - /usr/share/nuclei-templates/http/misconfiguration/  (Cors, debug endpoints, etc.)
    - /usr/share/nuclei-templates/http/default-logins/    (login admin trivial)
    - /usr/share/nuclei-templates/http/exposures/         (.git, .env, backups)
    - /usr/share/nuclei-templates/http/technologies/      (fingerprint de stack — ESTE es el nombre real)
    - /usr/share/nuclei-templates/http/cves/<año>/        (CVE acotado por año)
  * NO uses paths tipo /cves/cve-2023-*.yaml (raiz no existe). NO uses /usr/share/nuclei-templates/http/ entero (timeout).
  * El subdir de fingerprint se llama `technologies/`, NO `tech-detection/` (ese path NO existe). Para fingerprint rapido usa `whatweb --color=never https://TARGET`.
- Wordlists: /usr/share/wordlists/  (contiene nmap.lst, rockyou.txt.gz, seclists/)
  * NO existe /usr/share/wordlists/dirb/ ni /usr/share/wordlists/dirbuster/. Para fuzzing web usa SIEMPRE las rutas seclists de abajo.
  * seclists: /usr/share/seclists/Discovery/Web-Content/common.txt (1.7K paths)
  * seclists pequenitas: /usr/share/seclists/Discovery/Web-Content/quickhits.txt
  * Para fuerza bruta auth: /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
- ffuf: requiere literal `FUZZ` en la URL/wordlist. Ej: `ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -ac -t 20`
- whatweb: fingerprint HTTP (title, servidor, tecnologias, IP, status) — sustituye a httpx para esto.
  Una URL: `whatweb --color=never https://TARGET`
  Varias a la vez: `whatweb --color=never https://a.dom https://b.dom https://c.dom`
  Lista grande (output de subfinder): `subfinder -d TARGET -silent | sed 's#^#https://#' > /tmp/u.txt && whatweb --color=never --input-file=/tmp/u.txt`
  NO uses `httpx` para probing: el binario de este container es el cliente Python, no el de ProjectDiscovery (no tiene -title/-tech-detect/-threads).
- sqlmap: NO uses --max-retries (no existe). Si quieres acotado, `sqlmap -u "https://TARGET/?id=1" --level=2 --risk=1 --random-agent --batch --timeout=10`.
"""


def _build_osint_toolbox(objetivo: str) -> str:
    """Genera el bloque OSINT con el objetivo concreto sustituido para que el
    modelo NO tenga que improvisar el dominio (probabilidad de error baja con
    `dig +short {dominio}` literal en el prompt que con TARGET genérico)."""
    return f"""Herramientas y tecnicas obligatorias en esta fase OSINT (no ejecutes nmap ni nikto ni ffuf aqui, eso es Reconocimiento activo):
EJECUTA estos comandos en orden, en iteraciones separadas (uno por Action):
1. subfinder -d {objetivo} -silent      (descubre subdominios via API publicas — fuente principal)
2. theHarvester -d {objetivo} -b crtsh,duckduckgo -l 200   (subdominios + emails; NO uses bing, falla)
3. dig +short {objetivo} ; dig MX {objetivo} ; dig TXT {objetivo} ; dig NS {objetivo}
4. curl -s 'https://crt.sh/?q=%25.{objetivo}&output=json' | jq -r '.[].name_value' | sort -u | head -50
5. whois {objetivo}
6. whatweb --color=never https://{objetivo}
   (fingerprint: title, servidor, tecnologias, IP. NO uses `httpx`: el de este container es el cliente Python, no el de ProjectDiscovery.)
NO ejecutes `amass` aqui (paquete Kali roto con error libpostal_data — perderias 2 iteraciones).
NO uses dig/whois solo; OBLIGATORIO usar subfinder + theHarvester + crt.sh tambien, son las herramientas que descubren los activos no obvios.
NO toques aun nmap, ffuf, nuclei, nikto, sqlmap (eso va en fases siguientes).
"""


def _construir_prompt_inicial(
    fase: str, objetivo: str, scope: list[str], notas_dossier: str,
    budget_min_fase: float | None = None, max_iter: int | None = None,
    memoria_findings: str = "",
    comandos_previos: list[str] | None = None,
) -> str:
    bloque_tiempo = ""
    if budget_min_fase is not None:
        bloque_tiempo = (
            f"Budget de tiempo para esta fase: ~{budget_min_fase:.1f} minutos"
            f"{f' (max {max_iter} iteraciones)' if max_iter else ''}.\n"
        )
    bloque_memoria = ""
    if memoria_findings:
        bloque_memoria = "\n" + memoria_findings + "\n"

    bloque_osint = ""
    if fase.strip().lower() in ("osint", "reconocimiento osint"):
        bloque_osint = "\n" + _build_osint_toolbox(objetivo)

    bloque_previos = ""
    if comandos_previos:
        # Solo enseñamos los ultimos N para no consumir contexto. Cortamos a 60
        # chars/linea para que sea rapido de leer y rapido de contextualizar.
        ultimos = comandos_previos[-12:]
        listado = "\n".join(f"- $ {c[:120]}" for c in ultimos)
        bloque_previos = (
            "\nComandos ya ejecutados en fases anteriores (NO repitas, EVOLUCIONA):\n"
            f"{listado}\n"
            "Si necesitas el mismo banner, REUSA los hallazgos previos via memoria, no relances el comando.\n"
        )

    return (
        f"Fase actual: {fase}\n"
        f"Objetivo principal: {objetivo}\n"
        f"Scope autorizado: {', '.join(scope) if scope else objetivo}\n"
        f"{bloque_tiempo}"
        f"Contexto del dossier: {notas_dossier[:600] if notas_dossier else '(sin dossier)'}\n"
        f"{bloque_memoria}"
        f"{bloque_osint}"
        f"{bloque_previos}\n"
        "Empieza con tu primer Thought + Action."
    )


def _parsear_respuesta(texto: str) -> tuple[str | None, str | None]:
    th = RE_THOUGHT.search(texto)
    ac = RE_ACTION.search(texto)
    thought = th.group(1).strip() if th else None
    action  = ac.group(1).strip() if ac else None
    if action:
        # Limpia comillas, prefijos `$`, lineas en blanco al final
        action = action.strip().lstrip("$").strip()
        # Si vienen multilinea, tomamos solo la primera linea no vacia
        primeras = [l.strip() for l in action.splitlines() if l.strip()]
        action = primeras[0] if primeras else action
    return thought, action


def _formatear_observation(res: dict) -> str:
    out = res.get("stdout", "").strip()
    err = res.get("stderr", "").strip()
    rc  = res.get("returncode", -1)
    timeout = res.get("timeout_hit", False)
    bloques = [f"Observation: returncode={rc}{' (TIMEOUT)' if timeout else ''}"]
    if out:
        bloques.append("--- stdout ---\n" + out[:MAX_OBSERVATION_CHARS])
    if err:
        bloques.append("--- stderr ---\n" + err[:400])
    if not out and not err:
        bloques.append("(sin salida)")
    return "\n".join(bloques)


async def ejecutar_react(
    fase: str,
    objetivo: str,
    scope: list[str],
    notas_dossier: str = "",
    max_iter: int = 6,
    timeout_por_comando: int = 90,
    deadline_seg: float | None = None,
    engagement_id: str | None = None,
    comandos_previos: list[str] | None = None,
) -> dict:
    """Ejecuta un bucle ReAct y devuelve el historial estructurado.

    Si `deadline_seg` se proporciona, el bucle comprueba el reloj antes de
    cada iteracion y para limpiamente cuando se agota (en vez de cortar a
    mitad de inferencia).

    Returns: {
        "iteraciones": int,
        "turnos": [...], "stop_reason": ..., "evidencia_completa": [...]
    }
    """
    import time as _time
    inicio = _time.monotonic()

    budget_min = (deadline_seg / 60.0) if deadline_seg else None

    # Memory: retrieve top-3 findings semánticamente similares por objetivo+fase.
    # Fail-open: si memoria no responde, simplemente no añadimos nada al prompt.
    memoria_findings_txt = ""
    try:
        memoria_rows = await memory_store.retrieve(
            query=f"{fase} {objetivo}", fase=fase, objetivo=objetivo, top_k=3,
        )
        if memoria_rows:
            memoria_findings_txt = memory_store.format_for_prompt(memoria_rows)
            logger.info("memory: %d findings inyectados al Red (fase=%s)",
                        len(memoria_rows), fase)
    except Exception as e:
        logger.warning("memory.retrieve para Red falló: %s", e)

    messages = [
        {"role": "system", "content": SYSTEM_REACT},
        {"role": "user", "content": _construir_prompt_inicial(
            fase, objetivo, scope, notas_dossier,
            budget_min_fase=budget_min, max_iter=max_iter,
            memoria_findings=memoria_findings_txt,
            comandos_previos=comandos_previos,
        )},
    ]
    turnos: list[dict] = []
    evidencia: list[str] = []
    stop_reason = "max_iter"
    critic_stats = {"approve": 0, "advise": 0, "veto": 0, "calls": 0}

    for i in range(max_iter):
        if deadline_seg is not None and (_time.monotonic() - inicio) >= deadline_seg:
            stop_reason = "deadline"
            break
        try:
            respuesta = await ask_whiterabbit_chat(messages, max_tokens=400)
        except Exception as e:
            logger.exception("Fallo en ask_whiterabbit_chat: %s", e)
            stop_reason = "llm_error"
            break

        thought, action = _parsear_respuesta(respuesta)
        if not action:
            logger.warning("Iter %d: no pude parsear Action de: %r", i, respuesta[:200])
            messages.append({"role": "assistant", "content": respuesta})
            messages.append({"role": "user", "content": "No detecte 'Action:' en tu respuesta. Repite el formato exacto: Thought: ...\\nAction: <comando o FINAL>"})
            continue

        if action.upper().startswith("FINAL"):
            turnos.append({"thought": thought, "action": "FINAL", "observation_resumen": "(fin)", "returncode": 0, "ok": True})
            stop_reason = "final"
            break

        # ── Critic gate (opcional, env-controlled) ─────────────────────
        critic_hint = ""
        if critic_should_run(i, action):
            verdict = await evaluar_action(
                fase=fase, objetivo=objetivo, scope=scope,
                action=action, turnos_recientes=turnos,
                notas_dossier=notas_dossier,
                engagement_id=engagement_id,
            )
            critic_stats["calls"] += 1
            v = verdict["verdict"]
            critic_stats[v.lower()] = critic_stats.get(v.lower(), 0) + 1
            logger.info("Critic iter %d: %s — %s", i, v, verdict["reason"])

            if v == "VETO":
                # No ejecutamos. Inyectamos el motivo y damos otra iter al Red.
                turnos.append({
                    "thought": thought, "action": action,
                    "observation_resumen": f"(VETO Critic: {verdict['reason']})",
                    "returncode": -2, "ok": False, "critic_veto": True,
                })
                messages.append({"role": "assistant", "content": respuesta})
                messages.append({"role": "user", "content": (
                    f"Observation: tu comando fue VETADO por el revisor senior. "
                    f"Motivo: {verdict['reason']}. NO se ejecuto. Propon una alternativa.\n\n"
                    "Dame tu siguiente Thought + Action."
                )})
                continue
            if v == "ADVISE":
                critic_hint = f"\n[Critic ADVISE: {verdict['reason']}]"

        res = await ejecutar_comando(action, timeout=timeout_por_comando)
        observation = _formatear_observation(res)
        if critic_hint:
            observation = observation + critic_hint
        evidencia.append(f"$ {action}\n{observation}")

        turnos.append({
            "thought": thought,
            "action": action,
            "observation_resumen": (res.get("stdout", "")[:300] + ("..." if len(res.get("stdout", "")) > 300 else "")),
            "returncode": res.get("returncode", -1),
            "ok": res.get("ok", False),
            "timeout_hit": res.get("timeout_hit", False),
        })

        messages.append({"role": "assistant", "content": respuesta})
        messages.append({"role": "user", "content": observation + "\n\nDame tu siguiente Thought + Action (o FINAL)."})

    return {
        "iteraciones": len(turnos),
        "turnos": turnos,
        "stop_reason": stop_reason,
        "evidencia_completa": evidencia,
        "critic_stats": critic_stats if CRITIC_ENABLED else None,
    }
