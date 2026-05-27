"""Configura iptables OUTPUT del container pentest-tools al iniciar el engagement.

Politica:
  - DROP por defecto en OUTPUT
  - ACCEPT a loopback
  - ACCEPT established,related (responses)
  - ACCEPT a 53/udp,tcp (DNS, necesario para resolver targets)
  - ACCEPT a IPs resueltas de los repos apt/pip (necesario por la libertad
    de auto-instalacion de herramientas que decidio Auditor)
  - ACCEPT a cada IP/red del scope autorizado del cliente

Cualquier intento del modelo de tocar IPs fuera de scope se bloquea a nivel de
red (iptables, no en el LLM). Aunque WhiteRabbit "razone" un nmap a 8.8.8.8,
el SYN no sale del container.
"""

import asyncio
import socket
from .runner import ejecutar_comando

REPOS_APT = [
    "http.kali.org",
    "https.kali.org",
    "kali.download",
    "archive.kali.org",
    "security.kali.org",
    "deb.debian.org",
    "security.debian.org",
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
]

# APIs OSINT publicas necesarias para que subfinder/amass/theHarvester funcionen.
# Se whitelistsean en TODOS los engagements (no por fase) — el scope guard
# se aplica una sola vez al inicio. Trade-off: el modelo PODRIA usar estos
# dominios para algo no autorizado, pero estan limitados a busqueda pasiva
# sobre dominios publicos. Aceptable para auditoria autorizada con LLM
# supervisado. Smoke V3 (2026-05-23) confirmo que sin esto las OSINT tools
# fallan silenciosas o por timeout.
OSINT_PUBLIC_APIS = [
    "crt.sh",                       # Certificate Transparency (clave para subfinder/theHarvester)
    "dns.bufferover.run",
    "api.certspotter.com",
    "api.hackertarget.com",
    "hackertarget.com",
    "dnsdumpster.com",
    "web.archive.org",              # Wayback Machine (archive.org_data subfinder)
    "duckduckgo.com",
    "html.duckduckgo.com",
    "www.bing.com",                 # theHarvester bing engine
    "www.google.com",               # theHarvester google
    "search.brave.com",
    "otx.alienvault.com",
    "api.passivetotal.com",
    "rapiddns.io",
    "urlscan.io",
    "www.urlscan.io",
]


def _resolver_hostname(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return list({info[4][0] for info in infos})
    except socket.gaierror:
        return []


async def _resolver_async(host: str) -> list[str]:
    return await asyncio.get_event_loop().run_in_executor(None, _resolver_hostname, host)


def _es_ip(s: str) -> bool:
    try:
        socket.inet_aton(s.split("/")[0])
        return True
    except (socket.error, ValueError):
        return False


async def _ips_de_scope(targets: list[str]) -> list[str]:
    ips: set[str] = set()
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if _es_ip(t):
            ips.add(t)
            continue
        resueltas = await _resolver_async(t)
        ips.update(resueltas)
    return sorted(ips)


async def aplicar_scope(targets: list[str]) -> dict:
    """Aplica reglas iptables del scope autorizado al container pentest-tools.
    `targets` es una lista de IPs, redes (CIDR) o hostnames del cliente."""
    ips_apt: set[str] = set()
    for h in REPOS_APT:
        ips_apt.update(await _resolver_async(h))

    ips_osint: set[str] = set()
    for h in OSINT_PUBLIC_APIS:
        ips_osint.update(await _resolver_async(h))

    ips_scope = await _ips_de_scope(targets)

    if not ips_scope:
        return {"ok": False, "razon": "scope vacio o ningun target resoluble", "ips_scope": [], "ips_apt": sorted(ips_apt), "ips_osint": sorted(ips_osint)}

    comandos = [
        "iptables -F OUTPUT",
        "iptables -P OUTPUT DROP",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
        "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
    ]
    for ip in sorted(ips_apt):
        comandos.append(f"iptables -A OUTPUT -d {ip} -p tcp -m multiport --dports 80,443 -j ACCEPT")
    for ip in sorted(ips_osint):
        comandos.append(f"iptables -A OUTPUT -d {ip} -p tcp -m multiport --dports 80,443 -j ACCEPT")
    for ip in ips_scope:
        comandos.append(f"iptables -A OUTPUT -d {ip} -j ACCEPT")

    script = " && ".join(comandos)
    res = await ejecutar_comando(script, timeout=30)
    return {
        "ok": res["ok"],
        "ips_scope": ips_scope,
        "ips_apt": sorted(ips_apt),
        "ips_osint": sorted(ips_osint),
        "stderr": res["stderr"] if not res["ok"] else "",
    }


async def limpiar_scope() -> dict:
    """Resetea OUTPUT a ACCEPT (uso al cerrar engagement, antes de destruir container)."""
    script = "iptables -F OUTPUT && iptables -P OUTPUT ACCEPT"
    return await ejecutar_comando(script, timeout=10)
