"""
memory_store.py — Memoria semántica de findings de auditorías previas.

Backend: postgres local + pgvector. Service `ai_memory_memory-postgres` en el
swarm local del orchestrator, expuesto en 127.0.0.1:5433. Aislado del postgres
de la app principal (consultor_postgres en VPS2) — los findings no salen del
nodo del orchestrator.

Embedder: `intfloat/multilingual-e5-small` (384 dims) sobre CPU. Modelo
~117MB, latencia ~40-80ms por chunk en una CPU moderna. Multilingüe ES/EN.

Política fail-open: si la memoria no está disponible, las funciones devuelven
[] o no insertan, pero NUNCA lanzan excepción — el flujo del engagement
sigue. Filosofía: la memoria es un boost, no un requirement.

Uso:
  await init()                                    # al startup del orchestrator
  rows = await retrieve("nmap example.com", fase="recon", top_k=3)
  await upsert_chunk(texto, fase, objetivo, engagement_id, meta={...})
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import asyncpg

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────
DSN = os.getenv(
    "MEMORY_DB_DSN",
    "postgresql://memory:<REDACTED>@127.0.0.1:5433/memory",
)
MEMORY_ENABLED = os.getenv("MEMORY_ENABLED", "true").lower() in ("1", "true", "yes")
EMBED_MODEL_NAME = os.getenv("MEMORY_EMBED_MODEL", "intfloat/multilingual-e5-small")
EMBED_DIM = 384  # multilingual-e5-small

# Field-level encryption (pgcrypto). Si no hay key el módulo aborta init():
# preferimos fallar explícito a escribir hallazgos en plano sin querer.
_FIELD_KEY = os.getenv("DB_FIELD_KEY")

_pool: asyncpg.Pool | None = None
_embedder: Any = None  # SentenceTransformer
_embedder_lock = asyncio.Lock()


# ── Embedder ───────────────────────────────────────────────────────────────
def _get_embedder():
    """Lazy load para no pagar el coste si MEMORY_ENABLED=false."""
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        logger.info("memory: cargando embedder %s (~117MB, CPU)", EMBED_MODEL_NAME)
        _embedder = SentenceTransformer(EMBED_MODEL_NAME, device="cpu")
    return _embedder


async def _embed(text: str, *, is_query: bool = False) -> list[float]:
    """
    e5 requiere prefijos: 'query: ' para retrieval queries, 'passage: ' para
    documentos. Si no se respeta, la calidad cae mucho.
    """
    prefix = "query: " if is_query else "passage: "
    full = prefix + text.strip()[:4000]  # corta a 4k chars (~1k tokens)
    loop = asyncio.get_running_loop()
    emb = await loop.run_in_executor(
        None, lambda: _get_embedder().encode(full, normalize_embeddings=True)
    )
    return emb.tolist()


# ── Pool ───────────────────────────────────────────────────────────────────
async def init() -> bool:
    """Inicializa pool + crea tabla si no existe. Devuelve True si OK."""
    global _pool
    if not MEMORY_ENABLED:
        logger.info("memory: MEMORY_ENABLED=false → store desactivado")
        return False
    if not _FIELD_KEY:
        logger.warning("memory: DB_FIELD_KEY no definida → store deshabilitado (no escribir findings en plano)")
        return False
    try:
        _pool = await asyncpg.create_pool(DSN, min_size=1, max_size=4, timeout=10)
        async with _pool.acquire() as conn:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            await conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS pentest_memory (
                    id BIGSERIAL PRIMARY KEY,
                    engagement_id TEXT,
                    fase TEXT,
                    tipo_engagement TEXT,
                    objetivo TEXT,
                    texto_enc BYTEA NOT NULL,
                    embedding vector({EMBED_DIM}) NOT NULL,
                    meta_enc BYTEA,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS pentest_memory_emb_idx
                ON pentest_memory USING hnsw (embedding vector_cosine_ops);
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS pentest_memory_objetivo_idx
                ON pentest_memory (objetivo);
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS pentest_memory_fase_idx
                ON pentest_memory (fase);
            """)
        logger.info("memory: pool listo, schema OK (dim=%d)", EMBED_DIM)
        return True
    except Exception as exc:
        logger.warning("memory: init falló (fail-open): %s", exc)
        _pool = None
        return False


async def close() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def is_ready() -> bool:
    return MEMORY_ENABLED and _pool is not None


# ── API ────────────────────────────────────────────────────────────────────
async def upsert_chunk(
    texto: str,
    fase: str | None = None,
    objetivo: str | None = None,
    engagement_id: str | None = None,
    tipo_engagement: str | None = None,
    meta: dict | None = None,
) -> int | None:
    """Inserta un chunk con su embedding. Devuelve id o None si falla."""
    if not is_ready():
        return None
    try:
        emb = await _embed(texto, is_query=False)
    except Exception as exc:
        logger.warning("memory.upsert: embed falló: %s", exc)
        return None
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO pentest_memory
                  (texto_enc, embedding, fase, objetivo, engagement_id,
                   tipo_engagement, meta_enc)
                VALUES (pgp_sym_encrypt($1, $8),
                        $2::vector, $3, $4, $5, $6,
                        pgp_sym_encrypt($7, $8))
                RETURNING id;
                """,
                texto,
                "[" + ",".join(str(x) for x in emb) + "]",
                fase,
                objetivo,
                engagement_id,
                tipo_engagement,
                json.dumps(meta or {}),
                _FIELD_KEY,
            )
            return int(row["id"])
    except Exception as exc:
        logger.warning("memory.upsert: insert falló: %s", exc)
        return None


async def retrieve(
    query: str,
    *,
    fase: str | None = None,
    objetivo: str | None = None,
    tipo_engagement: str | None = None,
    top_k: int = 3,
    distance_max: float = 0.5,
) -> list[dict]:
    """Top-k chunks por similitud coseno + filtros opcionales.

    distance_max: cosine distance (0=idéntico, 1=ortogonal). Default 0.5 evita
    devolver chunks irrelevantes que arrastran ruido al prompt.
    """
    if not is_ready() or not query.strip():
        return []
    try:
        emb = await _embed(query, is_query=True)
    except Exception as exc:
        logger.warning("memory.retrieve: embed falló: %s", exc)
        return []
    vec_lit = "[" + ",".join(str(x) for x in emb) + "]"
    clauses = []
    args: list[Any] = [vec_lit]
    if fase:
        args.append(fase)
        clauses.append(f"fase = ${len(args)}")
    if objetivo:
        args.append(objetivo)
        clauses.append(f"objetivo = ${len(args)}")
    if tipo_engagement:
        args.append(tipo_engagement)
        clauses.append(f"tipo_engagement = ${len(args)}")
    args.append(distance_max)
    dist_pos = len(args)
    args.append(top_k)
    k_pos = len(args)
    args.append(_FIELD_KEY)
    key_pos = len(args)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id,
               pgp_sym_decrypt(texto_enc, ${key_pos}) AS texto,
               fase, objetivo, engagement_id,
               CASE WHEN meta_enc IS NULL THEN NULL
                    ELSE pgp_sym_decrypt(meta_enc, ${key_pos})::jsonb
               END AS meta,
               (embedding <=> $1::vector) AS distance
        FROM pentest_memory
        {where}
        {('AND' if clauses else 'WHERE')} (embedding <=> $1::vector) < ${dist_pos}
        ORDER BY embedding <=> $1::vector
        LIMIT ${k_pos};
    """
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(sql, *args)
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("memory.retrieve: query falló: %s", exc)
        return []


async def count() -> int:
    """Total chunks indexados — útil para diagnóstico."""
    if not is_ready():
        return 0
    try:
        async with _pool.acquire() as conn:
            return int(await conn.fetchval("SELECT COUNT(*) FROM pentest_memory"))
    except Exception:
        return 0


def format_for_prompt(rows: list[dict], max_chars_each: int = 400) -> str:
    """Formatea filas retrieve para inyectar al prompt del modelo."""
    if not rows:
        return ""
    lines = ["Findings similares de auditorías previas (top-k):"]
    for i, r in enumerate(rows, 1):
        txt = (r.get("texto") or "")[:max_chars_each].replace("\n", " ").strip()
        meta_bits = []
        if r.get("objetivo"):
            meta_bits.append(f"obj={r['objetivo']}")
        if r.get("fase"):
            meta_bits.append(f"fase={r['fase']}")
        meta = " (" + ", ".join(meta_bits) + ")" if meta_bits else ""
        lines.append(f"  [{i}]{meta} {txt}")
    return "\n".join(lines) + "\n"
