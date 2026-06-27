"""
Termina procesos clasificados como "Desconocido", a peticion explicita
del usuario (switch en la interfaz). Accion puntual e irreversible:
cierra los procesos que esten en pantalla en el momento de activarse,
no vigila conexiones futuras.
"""

from dataclasses import dataclass
from typing import List

import psutil


@dataclass
class BlockResult:
    pid: int
    name: str
    success: bool
    detail: str


def terminate_unknown(pids: List[int]) -> List[BlockResult]:
    results = []
    for pid in pids:
        try:
            p = psutil.Process(pid)
            name = p.name()
            p.terminate()
            try:
                p.wait(timeout=2)
                detail = "Proceso cerrado."
            except psutil.TimeoutExpired:
                detail = "Senal de cierre enviada (puede tardar en finalizar)."
            results.append(BlockResult(pid=pid, name=name, success=True, detail=detail))
        except psutil.NoSuchProcess:
            results.append(BlockResult(pid=pid, name="?", success=False, detail="El proceso ya no existia."))
        except psutil.AccessDenied:
            results.append(BlockResult(
                pid=pid, name="?", success=False,
                detail="Permiso denegado. Ejecuta la app como administrador para poder cerrarlo.",
            ))
        except Exception as exc:
            results.append(BlockResult(pid=pid, name="?", success=False, detail=str(exc)))
    return results
