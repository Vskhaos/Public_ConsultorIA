from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

@dataclass
class Hallazgo:
    titulo: str
    descripcion: str
    severidad: str  # critica, alta, media, baja, informativa
    fase: str
    recomendacion: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class Tarea:
    descripcion: str
    resultado: str
    fase: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class Engagement:
    id: str
    tipo: str
    objetivo: str
    tiempo_total_minutos: int
    tiempo_inicio: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    fase_actual: int = 0
    iteracion_actual: int = 0
    hallazgos: List[Hallazgo] = field(default_factory=list)
    tareas: List[Tarea] = field(default_factory=list)
    estado: str = "en_progreso"

    def tiempo_transcurrido_minutos(self) -> float:
        inicio = datetime.fromisoformat(self.tiempo_inicio)
        return (datetime.utcnow() - inicio).total_seconds() / 60

    def tiempo_restante_minutos(self) -> float:
        return self.tiempo_total_minutos - self.tiempo_transcurrido_minutos()

    def porcentaje_tiempo_usado(self) -> float:
        return (self.tiempo_transcurrido_minutos() / self.tiempo_total_minutos) * 100

    def hay_tiempo(self) -> bool:
        return self.tiempo_restante_minutos() > 2
