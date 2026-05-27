"""
limits.py — Rate limiter compartido (slowapi).

Si `REDIS_URL` está configurado, slowapi usa Redis como storage y los
contadores son consistentes entre las réplicas API (3/min real, no 12/min).
Sin REDIS_URL, fallback in-memory (counters por proceso → en swarm con
N réplicas el límite efectivo se multiplica por N).
"""
import os

from slowapi import Limiter
from slowapi.util import get_remote_address

_REDIS_URL = os.getenv("REDIS_URL", "").strip()

if _REDIS_URL:
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200/hour"],
        storage_uri=_REDIS_URL,
    )
else:
    limiter = Limiter(key_func=get_remote_address, default_limits=["200/hour"])
