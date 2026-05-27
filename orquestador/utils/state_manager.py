import redis
import json
from datetime import datetime

r = redis.Redis(host='0.0.0.0', port=6379, decode_responses=True)

def crear_engagement(engagement_id: str, tipo: str, objetivo: str, tiempo_minutos: int):
    estado = {
        "id": engagement_id,
        "tipo": tipo,
        "objetivo": objetivo,
        "tiempo_total": tiempo_minutos,
        "tiempo_inicio": datetime.utcnow().isoformat(),
        "fase_actual": 0,
        "fases_completadas": [],
        "hallazgos": [],
        "tareas_completadas": [],
        "estado": "en_progreso"
    }
    r.set(f"engagement:{engagement_id}", json.dumps(estado))
    return estado

def obtener_engagement(engagement_id: str) -> dict:
    data = r.get(f"engagement:{engagement_id}")
    if not data:
        raise ValueError(f"Engagement {engagement_id} no encontrado")
    return json.loads(data)

def actualizar_engagement(engagement_id: str, estado: dict):
    r.set(f"engagement:{engagement_id}", json.dumps(estado))

def añadir_hallazgo(engagement_id: str, hallazgo: dict):
    estado = obtener_engagement(engagement_id)
    estado["hallazgos"].append({
        **hallazgo,
        "timestamp": datetime.utcnow().isoformat()
    })
    actualizar_engagement(engagement_id, estado)

def añadir_tarea(engagement_id: str, tarea: str, resultado: str):
    estado = obtener_engagement(engagement_id)
    estado["tareas_completadas"].append({
        "tarea": tarea,
        "resultado": resultado,
        "timestamp": datetime.utcnow().isoformat()
    })
    actualizar_engagement(engagement_id, estado)

def eliminar_engagement(engagement_id: str):
    r.delete(f"engagement:{engagement_id}")

def tiempo_transcurrido_minutos(engagement_id: str) -> float:
    estado = obtener_engagement(engagement_id)
    inicio = datetime.fromisoformat(estado["tiempo_inicio"])
    ahora = datetime.utcnow()
    return (ahora - inicio).total_seconds() / 60

DOSSIER_TTL_SEG = 30 * 60

def set_dossier(ref: str, dossier: dict):
    r.setex(f"dossier:{ref}", DOSSIER_TTL_SEG, json.dumps(dossier))

def get_dossier(ref: str) -> dict | None:
    data = r.get(f"dossier:{ref}")
    return json.loads(data) if data else None

def eliminar_dossier(ref: str):
    r.delete(f"dossier:{ref}")
