"""
Resuelve el nombre de host (DNS inverso) de direcciones IP en la red
local para ayudar a identificar de que dispositivo se trata. Se
cachea y se resuelve en segundo plano para no bloquear la interfaz.
"""

import socket
import threading
from typing import Dict, Optional

PENDING = "pendiente"
NOT_FOUND = "(sin nombre)"

_CACHE: Dict[str, str] = {}
_LOCK = threading.Lock()


def get_cached(ip: str) -> Optional[str]:
    with _LOCK:
        return _CACHE.get(ip)


def request_lookup(ip: str) -> None:
    with _LOCK:
        if ip in _CACHE:
            return
        _CACHE[ip] = PENDING
    threading.Thread(target=_resolve, args=(ip,), daemon=True).start()


def _resolve(ip: str) -> None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        name = NOT_FOUND
    with _LOCK:
        _CACHE[ip] = name
