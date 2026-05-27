"""Ejecuta comandos dentro del container pentest-tools via docker exec.

El container es efimero por engagement. WhiteRabbit puede pedir cualquier comando
(incluido apt install para herramientas que no estan pre-instaladas). El
aislamiento descansa en (a) cgroups del container, (b) iptables egress filtrado
por scope_guard, (c) destruccion del container al cerrar el engagement.
"""

import asyncio
import shlex
from functools import lru_cache

SERVICE_NAME = "pentest_pentest-tools"
DEFAULT_TIMEOUT = 90
MAX_OUTPUT_CHARS = 6000  # ~1500 tokens, deja sitio al system + Thought


@lru_cache(maxsize=1)
def _service_label() -> str:
    return f"com.docker.swarm.service.name={SERVICE_NAME}"


async def _container_name() -> str | None:
    """Devuelve el nombre del container vivo del servicio pentest-tools.
    Busca en cada llamada para soportar restart/replica change."""
    proc = await asyncio.create_subprocess_exec(
        "docker", "ps",
        "--filter", f"label={_service_label()}",
        "--filter", "status=running",
        "--format", "{{.Names}}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, _ = await proc.communicate()
    nombres = [n for n in out.decode().strip().split("\n") if n]
    return nombres[0] if nombres else None


def _truncar(s: str, limite: int = MAX_OUTPUT_CHARS) -> str:
    if len(s) <= limite:
        return s
    cabeza = limite // 2
    cola = limite - cabeza - 100
    return f"{s[:cabeza]}\n\n[... {len(s) - limite} caracteres truncados ...]\n\n{s[-cola:]}"


async def ejecutar_comando(comando: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Ejecuta `comando` en el container pentest-tools.

    El comando se pasa a `sh -c` para soportar pipes, redirecciones y
    encadenamientos. El aislamiento legal/operativo se garantiza por scope_guard
    (iptables) y por el ciclo de vida efimero del container, NO por filtrado de
    sintaxis aqui.

    Devuelve dict serializable: {ok, returncode, stdout, stderr, comando, timeout_hit}.
    """
    nombre = await _container_name()
    if not nombre:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": "Container pentest-tools no encontrado o no esta corriendo.",
            "comando": comando,
            "timeout_hit": False,
        }

    proc = await asyncio.create_subprocess_exec(
        "docker", "exec", nombre, "sh", "-c", comando,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    timeout_hit = False
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        timeout_hit = True
        proc.kill()
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
        except asyncio.TimeoutError:
            stdout, stderr = b"", b"timeout interno al matar proceso"

    return {
        "ok": (proc.returncode == 0) and not timeout_hit,
        "returncode": proc.returncode if proc.returncode is not None else -1,
        "stdout": _truncar(stdout.decode(errors="replace")),
        "stderr": _truncar(stderr.decode(errors="replace"), limite=2000),
        "comando": comando,
        "timeout_hit": timeout_hit,
    }


async def reiniciar_container() -> bool:
    """Fuerza recreacion del container al cerrar engagement (wipe estado/tools instaladas)."""
    proc = await asyncio.create_subprocess_exec(
        "docker", "service", "update", "--force", "--detach", SERVICE_NAME,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0
