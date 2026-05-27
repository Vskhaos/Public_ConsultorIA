"""Indexa retroactivamente los informe_tecnico.md de informes_local/ al
memory store. Pensado para correr UNA vez al activar memoria, o tras
algún reset del schema.

Idempotencia: si el chunk ya existe, lo reinserta (la tabla es append-only sin
dedupe por hash). Para evitar duplicados, borra primero la tabla o haz
SELECT count antes/después.

Uso:
  cd /home/auditor/ai_pentest/orchestrator
  ./venv/bin/python scripts/index_historicos.py
"""
from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

# Permite importar módulos del orquestador desde este script
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

from utils import memory_store
from orquestador import _indexar_informe_en_memoria  # type: ignore

INFORMES_DIR = SCRIPT_DIR.parent / "informes_local"

# Fases que el orquestador usa para etiquetar chunks (heurística por kw).
FASES_DEFAULT = [
    "Reconocimiento",
    "Enumeración",
    "Análisis de vulnerabilidades",
    "Explotación controlada",
    "Documentación",
]


def parsear_head(md: str) -> tuple[str, str]:
    """Extrae (tipo, objetivo) del head de un informe_tecnico.md.
    Devuelve ('unknown', 'unknown') si no encuentra."""
    tipo_match = re.search(r"\|\s*Tipo\s*\|\s*([^|]+?)\s*\|", md)
    obj_match = re.search(r"\|\s*Objetivo\s*\|\s*([^|]+?)\s*\|", md)
    tipo = tipo_match.group(1).strip() if tipo_match else "unknown"
    obj = obj_match.group(1).strip() if obj_match else "unknown"
    return tipo, obj


async def main() -> None:
    ok = await memory_store.init()
    if not ok:
        print("memory_store no disponible — abortando")
        return

    pre_count = await memory_store.count()
    print(f"Memoria pre-indexado: {pre_count} chunks")

    total_chunks = 0
    total_engagements = 0
    for engagement_dir in sorted(INFORMES_DIR.iterdir()):
        if not engagement_dir.is_dir():
            continue
        informe = engagement_dir / "informe_tecnico.md"
        if not informe.exists():
            print(f"  {engagement_dir.name}: sin informe_tecnico.md, salto")
            continue

        eng_id = engagement_dir.name
        md = informe.read_text(encoding="utf-8")
        tipo, objetivo = parsear_head(md)

        chunks = await _indexar_informe_en_memoria(
            md, eng_id, tipo, objetivo, FASES_DEFAULT
        )
        print(f"  {eng_id}: tipo={tipo}, objetivo={objetivo[:50]}, chunks={chunks}")
        total_chunks += chunks
        total_engagements += 1

    post_count = await memory_store.count()
    print(f"\nMemoria post-indexado: {post_count} chunks "
          f"(+{post_count - pre_count} nuevos)")
    print(f"Engagements indexados: {total_engagements}, chunks insertados: {total_chunks}")

    await memory_store.close()


if __name__ == "__main__":
    asyncio.run(main())
