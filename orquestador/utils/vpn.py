"""Gestion de tuneles WireGuard del cliente para engagements internos.

Flujo:
  - T-20 (preload): si el engagement requiere VPN, descargar wg_config del
    cliente desde MinIO, escribir en /etc/wireguard/<iface>.conf, levantar con
    `wg-quick up`, validar handshake, marcar Redis como vpn:<ref>=ready.
  - T-fin (cleanup): bajar tunel, wipe del config (shred -u).

El config NO se guarda en disco mas alla del ciclo de vida del engagement.

Privilegios: el orquestador corre como auditor (systemd User=auditor). wg-quick y la
escritura/borrado de /etc/wireguard/ requieren root, asi que se invocan via
sudo NOPASSWD restringido en /etc/sudoers.d/orchestrator-vpn (ver Promptconsultoria).
"""

import asyncio
import logging
import os
import re
import time

from minio.error import S3Error

from utils.intel import _minio_client, MINIO_BUCKET
from utils.state_manager import r as redis_client

logger = logging.getLogger(__name__)

WG_DIR = "/etc/wireguard"
HANDSHAKE_MAX_AGE_S = 30  # un handshake mas viejo que esto es tunel "muerto"
# TTL de la marca vpn:<ref> en Redis. El teardown (bajar_wg en start.finally y
# cleanup_job) solo actúa si esta marca sigue siendo "ready", así que el TTL DEBE
# superar (lead de preload + duración máxima del engagement) o el túnel se queda
# huérfano. Bug 2026-05-25: estaba a 30 min — menor que el gap preload(T-20)→fin
# de run, así que en cualquier auditoría >~10 min la marca caducaba y el túnel no
# se bajaba. 48 h cubre incluso engagements de 24 h. La clave la borra bajar_wg en
# el teardown normal; el TTL solo es red de seguridad para marcas huérfanas.
VPN_TTL_SEG = 48 * 60 * 60
HELPER = "/usr/local/sbin/orchestrator-wg-helper"


def _ref_short(ref: str) -> str:
    """Normaliza ref para el helper (alfanumerico, max 11 chars)."""
    return re.sub(r"[^A-Za-z0-9]", "", ref)[:11]


def _iface_name(ref: str) -> str:
    """Convierte ref (ej. AUD-A3SOZY) en nombre de interfaz wg valido (<=15 chars)."""
    return f"eng_{_ref_short(ref)}"


def _config_path(ref: str) -> str:
    return f"{WG_DIR}/{_iface_name(ref)}.conf"


def set_vpn_state(ref: str, estado: str) -> None:
    redis_client.setex(f"vpn:{ref}", VPN_TTL_SEG, estado)


def get_vpn_state(ref: str) -> str | None:
    val = redis_client.get(f"vpn:{ref}")
    return val.decode() if val else None


async def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", "timeout"
    return (proc.returncode or 0), out.decode(errors="replace"), err.decode(errors="replace")


def _descargar_config(ref: str) -> bytes | None:
    """Descarga el wg_config.conf del cliente desde MinIO (no lo escribe a disco)."""
    cli = _minio_client()
    try:
        resp = cli.get_object(MINIO_BUCKET, f"{ref}/wg_config.conf")
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()
    except S3Error as e:
        logger.warning("No hay wg_config para %s: %s", ref, e)
        return None


async def _escribir_config(ref: str, contenido: bytes) -> bool:
    """Escribe config WG via helper privilegiado (write action lee de stdin)."""
    proc = await asyncio.create_subprocess_exec(
        "sudo", "-n", HELPER, "write", _ref_short(ref),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, err_b = await asyncio.wait_for(proc.communicate(input=contenido), timeout=10)
    except asyncio.TimeoutError:
        proc.kill()
        return False
    if proc.returncode != 0:
        logger.error("helper write fallo: %s", err_b.decode(errors="replace"))
        return False
    return True


async def _ultimo_handshake(ref: str) -> int | None:
    """Devuelve segundos desde el ultimo handshake del peer, o None si nunca."""
    rc, out, _ = await _run(["sudo", "-n", HELPER, "handshake", _ref_short(ref)], timeout=5)
    if rc != 0 or not out.strip():
        return None
    try:
        ts = int(out.strip().split()[-1])
        if ts == 0:
            return None
        return int(time.time()) - ts
    except (ValueError, IndexError):
        return None


async def levantar_wg(ref: str) -> dict:
    """Descarga el config, levanta el tunel, valida handshake. Devuelve estado."""
    iface = _iface_name(ref)

    contenido = _descargar_config(ref)
    if contenido is None:
        set_vpn_state(ref, "not_required")
        return {"ok": True, "estado": "not_required", "iface": iface, "razon": "cliente no aporto wg_config"}

    if not await _escribir_config(ref, contenido):
        set_vpn_state(ref, "failed")
        return {"ok": False, "estado": "failed", "iface": iface, "razon": "no se pudo escribir config (helper?)"}

    rc, _, err = await _run(["sudo", "-n", HELPER, "up", _ref_short(ref)], timeout=30)
    if rc != 0:
        await _wipe_config(ref)
        set_vpn_state(ref, "failed")
        return {"ok": False, "estado": "failed", "iface": iface, "razon": f"wg-quick up fallo: {err.strip()[:200]}"}

    # Esperar handshake (PersistentKeepalive=25 + tiempo handshake real ~3-5s)
    for intento in range(8):
        await asyncio.sleep(4)
        edad = await _ultimo_handshake(ref)
        if edad is not None and edad <= HANDSHAKE_MAX_AGE_S:
            set_vpn_state(ref, "ready")
            return {"ok": True, "estado": "ready", "iface": iface, "handshake_age_s": edad}
        logger.info("Esperando handshake en %s (intento %d, edad=%s)", iface, intento + 1, edad)

    # Tunel up pero sin handshake → bajamos para no dejar interfaz colgada
    await bajar_wg(ref)
    set_vpn_state(ref, "failed")
    return {"ok": False, "estado": "failed", "iface": iface, "razon": "wg-quick up OK pero sin handshake en 32s"}


async def bajar_wg(ref: str) -> dict:
    """Baja tunel y wipea config."""
    iface = _iface_name(ref)
    rc, _, err = await _run(["sudo", "-n", HELPER, "down", _ref_short(ref)], timeout=15)
    wipe_ok = await _wipe_config(ref)
    redis_client.delete(f"vpn:{ref}")
    return {"ok": rc == 0, "wipe_ok": wipe_ok, "iface": iface, "stderr": err.strip()[:200]}


async def _wipe_config(ref: str) -> bool:
    rc, _, _ = await _run(["sudo", "-n", HELPER, "wipe", _ref_short(ref)], timeout=5)
    return rc == 0
