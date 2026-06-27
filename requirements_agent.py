"""
Agente 1 - Definidor de Requisitos.

Asume criterios predeterminados de monitoreo de trafico de red sin
solicitar configuracion al usuario. El resultado (MonitoringRequirements)
es el contrato que consume el Agente 2 (Arquitecto de Flujo).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class MonitoringRequirements:
    refresh_interval_seconds: float = 2.0
    track_interfaces: bool = True
    track_connections: bool = True
    max_connections_listed: int = 100
    bandwidth_alert_mbps: float = 50.0
    connection_count_alert: int = 200
    log_to_file: bool = True
    log_path: str = "network_monitor_log.csv"
    classify_processes: bool = True
    detect_other_systems: bool = True
    track_egress: bool = True
    egress_log_path: str = "egress_log.csv"
    detect_attacks: bool = True
    attack_window_seconds: int = 60
    port_scan_threshold: int = 6
    brute_force_threshold: int = 5
    attack_log_path: str = "attack_log.csv"


def define_requirements() -> MonitoringRequirements:
    return MonitoringRequirements()
