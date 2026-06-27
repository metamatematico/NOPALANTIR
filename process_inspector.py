"""
Inspector de procesos a demanda. Cuando el usuario quiere saber
"quien es" un programa (por ejemplo, algo clasificado como
"Desconocido"), esta funcion reune toda la informacion disponible
para decidir si conviene restringirle el acceso a la red.
"""

import time
from dataclasses import dataclass
from typing import Optional

import psutil


@dataclass
class ProcessDetail:
    pid: int
    name: str
    exe: str
    username: str
    cmdline: str
    started: str
    parent_pid: Optional[int]
    parent_name: str
    num_connections: int
    error: str = ""


def _safe(getter, default="(sin acceso)"):
    try:
        return getter()
    except (psutil.AccessDenied, OSError, psutil.NoSuchProcess):
        return default


def inspect_process(pid: int) -> ProcessDetail:
    if not pid:
        return ProcessDetail(
            pid=0, name="(sin proceso)", exe="-", username="-", cmdline="-",
            started="-", parent_pid=None, parent_name="-", num_connections=0,
            error="Esta conexion no esta asociada a un PID visible.",
        )
    try:
        p = psutil.Process(pid)
        name = _safe(p.name, "?")
        exe = _safe(p.exe)
        username = _safe(p.username)
        cmdline = _safe(lambda: " ".join(p.cmdline()) or "(sin argumentos)")
        started = _safe(lambda: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.create_time())))

        parent = _safe(p.parent, None)
        parent_pid = parent.pid if parent else None
        parent_name = _safe(parent.name, "-") if parent else "-"

        try:
            num_connections = len(p.net_connections(kind="inet"))
        except (psutil.AccessDenied, OSError, AttributeError):
            num_connections = _safe(lambda: len(p.connections(kind="inet")), -1)

        return ProcessDetail(
            pid=pid, name=name, exe=exe, username=username, cmdline=cmdline,
            started=started, parent_pid=parent_pid, parent_name=parent_name,
            num_connections=num_connections,
        )
    except psutil.NoSuchProcess:
        return ProcessDetail(
            pid=pid, name="(finalizado)", exe="-", username="-", cmdline="-",
            started="-", parent_pid=None, parent_name="-", num_connections=0,
            error="El proceso ya no existe (termino despues de la ultima lectura).",
        )
    except psutil.AccessDenied:
        return ProcessDetail(
            pid=pid, name="(sin acceso)", exe="-", username="-", cmdline="-",
            started="-", parent_pid=None, parent_name="-", num_connections=0,
            error="Acceso denegado. Ejecuta la app como administrador para ver mas detalle.",
        )
