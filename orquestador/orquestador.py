"""Orquestador principal del engagement.

Flujo nuevo (2026-05-02): cada fase NO-documentacion lanza un bucle ReAct sobre
WhiteRabbit que ejecuta comandos REALES en el container pentest-tools, con
scope iptables aplicado. La evidencia (comandos + outputs reales) se acumula
y al final DeepSeek genera dos informes (tecnico + ejecutivo).
"""
import asyncio
import logging
import uuid
from datetime import datetime

from utils.state_manager import (
    crear_engagement, eliminar_engagement, eliminar_dossier,
)
from utils.model_client import ask_whiterabbit
from utils.reporting import generar_informe_tecnico, generar_informe_ejecutivo
from utils import memory_store
from phases.plantillas import obtener_fases
from models.engagement import Engagement
from tools.scope_guard import aplicar_scope, limpiar_scope
from tools.react_loop import ejecutar_react, SYSTEM_REACT
from tools.runner import reiniciar_container

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_COMANDO = 180
MAX_ITER_HARD_CAP = 50
MIN_ITER_POR_FASE = 2
BUDGET_MIN_SEG = 180
BUDGET_MAX_SEG = 3600
MIN_POR_ITER_ESPERADO = 1.5  # Qwen3-14B-AWQ hace iter en ~30-60s, no 3 min como
                             # asumía el diseño original con DeepSeek/WhiteRabbit.


def _max_iter_por_fase(peso_tiempo: float, tiempo_contratado_min: int) -> int:
    # Escala con tiempo contratado, pero con un piso (peso_tiempo * 72) que
    # preserva el comportamiento útil para engagements cortos (30-60 min).
    # Sube de *40 a *72 (2026-05-24) para que el límite real sea el deadline de
    # tiempo por fase, no el tope de iteraciones: Goblin/Wazoo cerraban a 24/10
    # de 60 min porque tocaban max_iter (no deadline) en OSINT/Recon/Explotación.
    iter_proporcional = int(tiempo_contratado_min * peso_tiempo / MIN_POR_ITER_ESPERADO)
    iter_floor = int(peso_tiempo * 72)
    return max(MIN_ITER_POR_FASE, min(MAX_ITER_HARD_CAP, max(iter_proporcional, iter_floor)))


async def _warmup_whiterabbit():
    """Una llamada trivial para que la primera inferencia real no pague cold start."""
    try:
        await ask_whiterabbit("Responde solo: OK", SYSTEM_REACT)
        logger.info("Warmup WhiteRabbit OK")
    except Exception as e:
        logger.warning("Warmup WhiteRabbit fallo (no critico): %s", e)


def _es_fase_documentacion(nombre: str) -> bool:
    return nombre.lower().startswith("documentación") or nombre.lower().startswith("documentacion")


def _chunkear(texto: str, target_chars: int = 600, overlap: int = 80) -> list[str]:
    """Split por párrafos primero, luego trocea si queda largo. Solape de
    `overlap` chars entre chunks para preservar contexto al borde."""
    parrafos = [p.strip() for p in texto.split("\n\n") if p.strip()]
    chunks: list[str] = []
    buffer = ""
    for p in parrafos:
        if len(buffer) + len(p) + 2 <= target_chars:
            buffer = (buffer + "\n\n" + p).strip() if buffer else p
        else:
            if buffer:
                chunks.append(buffer)
            if len(p) > target_chars:
                start = 0
                while start < len(p):
                    chunks.append(p[start:start + target_chars])
                    start += target_chars - overlap
                buffer = ""
            else:
                buffer = p
    if buffer:
        chunks.append(buffer)
    return chunks


async def _indexar_informe_en_memoria(
    informe_tecnico: str, engagement_id: str, tipo: str, objetivo: str,
    fases_orden: list[str],
) -> int:
    """Chunkea el informe técnico y lo inserta en memory_store. Etiqueta cada
    chunk con la fase más cercana (heurística por keywords) si la encuentra,
    si no, fase=None."""
    if not informe_tecnico or not memory_store.is_ready():
        return 0
    chunks = _chunkear(informe_tecnico, target_chars=600, overlap=80)
    fase_kw = {f.lower(): f for f in fases_orden}
    insertados = 0
    for ch in chunks:
        ch_lower = ch.lower()
        fase_hit = next((orig for kw, orig in fase_kw.items() if kw in ch_lower), None)
        rid = await memory_store.upsert_chunk(
            texto=ch, fase=fase_hit, objetivo=objetivo,
            engagement_id=engagement_id, tipo_engagement=tipo,
            meta={"origen": "informe_tecnico"},
        )
        if rid:
            insertados += 1
    return insertados


async def ejecutar_engagement(
    tipo: str,
    objetivo: str,
    tiempo_minutos: int,
    dossier: dict | None = None,
    ref: str | None = None,
    scope_extra: list[str] | None = None,
) -> dict:
    """Ejecuta el engagement completo. Devuelve {tecnico, ejecutivo}."""
    engagement_id = str(uuid.uuid4())[:8]
    fases = obtener_fases(tipo)
    crear_engagement(engagement_id, tipo, objetivo, tiempo_minutos)
    engagement = Engagement(
        id=engagement_id, tipo=tipo, objetivo=objetivo,
        tiempo_total_minutos=tiempo_minutos,
    )

    contexto_msg = " (con dossier preload)" if dossier else " (sin preload)"
    logger.info("[%s] Iniciando %s sobre %s - %d min%s",
                engagement_id, tipo, objetivo, tiempo_minutos, contexto_msg)

    scope_targets = [objetivo] + (scope_extra or [])
    notas_dossier = dossier.get("texto_destilado", "") if dossier else ""

    # 1. Aplicar scope al container pentest-tools (en paralelo con warmup)
    logger.info("[%s] Aplicando scope + warmup WhiteRabbit...", engagement_id)
    res_scope, _ = await asyncio.gather(
        aplicar_scope(scope_targets),
        _warmup_whiterabbit(),
    )
    if not res_scope.get("ok"):
        razon = res_scope.get("razon", "scope no aplicable")
        logger.error("Scope guard fallo: %s", razon)
        notas_dossier = f"⚠️ AVISO: scope_guard fallo ({razon}). Egress no restringido.\n\n{notas_dossier}"
    else:
        logger.info("[%s] Scope: %d IPs scope, %d IPs apt, %d IPs OSINT",
                    engagement_id, len(res_scope['ips_scope']),
                    len(res_scope['ips_apt']), len(res_scope.get('ips_osint', [])))

    # 2. Bucle por fases (excepto Documentacion, que es el reporting)
    evidencia_por_fase: dict[str, list[str]] = {}
    fases_orden_para_informe: list[str] = []
    # Comandos ejecutados acumulados, se pasan al ReAct de cada fase
    # siguiente para inhibir repeticion (smoke 2026-05-23: el mismo
    # `nmap -T4 --top-ports 100` aparecio en 4 fases distintas).
    comandos_acumulados: list[str] = []

    for i, fase in enumerate(fases):
        tiempo_restante_min = engagement.tiempo_restante_minutos()
        if tiempo_restante_min <= 0.5:
            logger.info("[%s] Tiempo agotado (%.1f min), no entramos en %s",
                        engagement_id, tiempo_restante_min, fase['nombre'])
            break
        if _es_fase_documentacion(fase["nombre"]):
            continue

        engagement.fase_actual = i
        max_iter = _max_iter_por_fase(fase["peso_tiempo"], tiempo_minutos)
        # Budget = peso * tiempo_restante, con min/max amplios para no cortar pre-1ª iter
        budget_fase_seg = max(BUDGET_MIN_SEG, min(int(tiempo_restante_min * 60 * fase["peso_tiempo"]), BUDGET_MAX_SEG))
        logger.info("[%s] === FASE %d/%d: %s (max_iter=%d, budget=%ds) ===",
                    engagement_id, i + 1, len(fases), fase['nombre'], max_iter, budget_fase_seg)

        try:
            # deadline_seg dentro del bucle: corta limpio entre iteraciones,
            # no a mitad de inferencia LLM. asyncio.wait_for externo solo como
            # red de seguridad muy holgada.
            resultado = await asyncio.wait_for(
                ejecutar_react(
                    fase=fase["nombre"],
                    objetivo=objetivo,
                    scope=scope_targets,
                    notas_dossier=notas_dossier,
                    max_iter=max_iter,
                    timeout_por_comando=DEFAULT_TIMEOUT_COMANDO,
                    deadline_seg=budget_fase_seg,
                    engagement_id=engagement_id,
                    comandos_previos=list(comandos_acumulados),
                ),
                timeout=budget_fase_seg + 120,
            )
        except asyncio.TimeoutError:
            logger.warning("[%s] Fase %s cortada (red de seguridad). Sin evidencia.",
                           engagement_id, fase['nombre'])
            resultado = {"iteraciones": 0, "turnos": [], "stop_reason": "phase_timeout_hard", "evidencia_completa": []}
        except Exception as e:
            logger.exception("ReAct fallo en fase %s: %s", fase["nombre"], e)
            resultado = {"iteraciones": 0, "turnos": [], "stop_reason": "exception", "evidencia_completa": []}

        evidencia_por_fase[fase["nombre"]] = resultado["evidencia_completa"]
        fases_orden_para_informe.append(fase["nombre"])
        # Extraer comandos de la evidencia (`$ comando\nObservation: ...`)
        # para alimentar el anti-repeticion de la siguiente fase.
        for ev in resultado["evidencia_completa"]:
            primera = ev.split("\n", 1)[0].strip()
            if primera.startswith("$ "):
                comandos_acumulados.append(primera[2:].strip())
        logger.info("[%s] %s: %d iter, stop=%s, evidencia=%d comandos",
                    engagement_id, fase['nombre'], resultado['iteraciones'],
                    resultado['stop_reason'], len(resultado['evidencia_completa']))

    # 3. Two-stage reporting con DeepSeek
    logger.info("[%s] Generando informe tecnico...", engagement_id)
    tiempo_usado = engagement.tiempo_transcurrido_minutos()
    informe_tecnico = await generar_informe_tecnico(
        tipo=tipo,
        objetivo=objetivo,
        tiempo_usado_min=tiempo_usado,
        tiempo_total_min=tiempo_minutos,
        fases_orden=fases_orden_para_informe,
        evidencia_por_fase=evidencia_por_fase,
        dossier=dossier,
    )
    logger.info("[%s] Generando informe ejecutivo...", engagement_id)
    informe_ejecutivo = await generar_informe_ejecutivo(
        tipo=tipo, objetivo=objetivo, informe_tecnico=informe_tecnico,
    )

    # 4. Indexar informe técnico en memory store (chunks ~600 chars con solape).
    #    Fail-open + timeout: si memoria responde lento o falla, no bloquea cierre.
    try:
        chunks_insertados = await asyncio.wait_for(
            _indexar_informe_en_memoria(
                informe_tecnico, engagement_id, tipo, objetivo,
                fases_orden_para_informe,
            ),
            timeout=60,
        )
        if chunks_insertados:
            logger.info("[%s] Memoria: %d chunks indexados", engagement_id, chunks_insertados)
    except asyncio.TimeoutError:
        logger.warning("[%s] memoria indexer timeout (60s), continuando", engagement_id)
    except Exception as e:
        logger.warning("memoria indexer falló (no critico): %s", e)

    # 5. Limpieza — con timeout defensivo. Si limpiar_scope se cuelga (caso real
    #    observado en AUD-25: 2h41 colgado), no bloquea el cierre del engagement.
    logger.info("[%s] Limpiando scope y recreando container pentest-tools...", engagement_id)
    try:
        await asyncio.wait_for(limpiar_scope(), timeout=30)
    except asyncio.TimeoutError:
        logger.warning("[%s] limpiar_scope timeout (30s), continuando con cleanup", engagement_id)
    except Exception as e:
        logger.warning("[%s] limpiar_scope falló (%s), continuando", engagement_id, e)
    # Recreacion async best-effort: borra estado/tools instaladas para el siguiente engagement
    asyncio.create_task(reiniciar_container())

    eliminar_engagement(engagement_id)
    if ref:
        eliminar_dossier(ref)

    logger.info("[%s] Engagement finalizado en %.0f min", engagement_id, tiempo_usado)
    return {"tecnico": informe_tecnico, "ejecutivo": informe_ejecutivo}


if __name__ == "__main__":
    async def _main():
        res = await ejecutar_engagement(
            tipo="pentesting_externo",
            objetivo="example.com",
            tiempo_minutos=10,
        )
        print("\n=== INFORME TECNICO ===\n")
        print(res["tecnico"])
        print("\n=== INFORME EJECUTIVO ===\n")
        print(res["ejecutivo"])

    asyncio.run(_main())
