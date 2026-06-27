"""
Agente 2 - Arquitecto de Flujo.

Traduce los requisitos del Agente 1 en un flujo de trabajo estandar y
ordenado. El Agente 3 (Generador de Codigo) implementa cada paso.
"""

from dataclasses import dataclass
from typing import List

from requirements_agent import MonitoringRequirements


@dataclass
class WorkflowStep:
    name: str
    description: str


@dataclass
class MonitoringWorkflow:
    requirements: MonitoringRequirements
    steps: List[WorkflowStep]


def build_workflow(requirements: MonitoringRequirements) -> MonitoringWorkflow:
    steps = [
        WorkflowStep("collect_io_counters", "Leer contadores de bytes/paquetes por interfaz"),
        WorkflowStep("compute_rates", "Calcular tasa de subida/bajada (Mbps) desde la ultima lectura"),
        WorkflowStep("collect_connections", "Listar conexiones activas (PID, proceso, local, remoto, estado)"),
        WorkflowStep("classify_processes", "Agrupar las conexiones por tipo de programa (navegador, mensajeria, sistema, etc.)"),
        WorkflowStep("detect_remote_systems", "Identificar direcciones remotas en la red local que no pertenecen a este equipo"),
        WorkflowStep("track_egress", "Registrar quien, cuando, desde donde y cuanto (aprox.) se transfiere hacia sistemas externos"),
        WorkflowStep("detect_attacks", "Analizar patrones de escaneo de puertos y fuerza bruta para detectar posibles ataques"),
        WorkflowStep("evaluate_alerts", "Comparar tasas, num. de conexiones y dispositivos nuevos contra los umbrales definidos"),
        WorkflowStep("update_ui", "Refrescar la interfaz con los datos calculados"),
        WorkflowStep("persist_log", "Anexar una fila al log CSV si log_to_file esta activo"),
    ]
    if not requirements.track_interfaces:
        steps = [s for s in steps if s.name not in ("collect_io_counters", "compute_rates")]
    if not requirements.track_connections:
        steps = [s for s in steps if s.name not in (
            "collect_connections", "classify_processes", "detect_remote_systems",
            "track_egress", "detect_attacks",
        )]
    if not requirements.classify_processes:
        steps = [s for s in steps if s.name != "classify_processes"]
    if not requirements.detect_other_systems:
        steps = [s for s in steps if s.name != "detect_remote_systems"]
    if not requirements.track_egress:
        steps = [s for s in steps if s.name != "track_egress"]
    if not requirements.detect_attacks:
        steps = [s for s in steps if s.name != "detect_attacks"]
    return MonitoringWorkflow(requirements=requirements, steps=steps)
