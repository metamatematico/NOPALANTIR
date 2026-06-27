"""
Resuelve datos geograficos aproximados para direcciones IP publicas
usando el servicio gratuito ip-api.com (sin registro, sin clave).
Las IPs privadas/locales no se consultan: no tienen geolocalizacion
util. Los resultados se cachean en memoria para no repetir consultas
a la misma IP en cada lectura, y se resuelven en segundo plano para
no bloquear la interfaz.
"""

import ipaddress
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional, Union

PENDING = "pendiente"
ERROR = "error"


@dataclass
class GeoInfo:
    country: str
    region: str
    city: str
    isp: str

    def label(self) -> str:
        parts = [p for p in (self.city, self.region, self.country) if p]
        return ", ".join(parts) if parts else "Desconocido"


_CACHE: Dict[str, Union[GeoInfo, str]] = {}
_OWN_LOCATION_CACHE: Dict[str, Union[GeoInfo, str]] = {}
_LOCK = threading.Lock()


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def _query(url: str) -> Union[GeoInfo, str]:
    try:
        with urllib.request.urlopen(url, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") == "success":
            return GeoInfo(
                country=data.get("country", ""), region=data.get("regionName", ""),
                city=data.get("city", ""), isp=data.get("isp", ""),
            )
        return ERROR
    except (urllib.error.URLError, ValueError, OSError):
        return ERROR


def get_cached(ip: str) -> Optional[Union[GeoInfo, str]]:
    with _LOCK:
        return _CACHE.get(ip)


def request_lookup(ip: str) -> None:
    """Encola (si hace falta) una busqueda asincrona de geolocalizacion para esta IP."""
    if not ip or not _is_public(ip):
        return
    with _LOCK:
        if ip in _CACHE:
            return
        _CACHE[ip] = PENDING
    threading.Thread(target=_fetch_ip, args=(ip,), daemon=True).start()


def _fetch_ip(ip: str) -> None:
    info = _query(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp")
    with _LOCK:
        _CACHE[ip] = info


def get_own_location() -> Union[GeoInfo, str]:
    """Geolocaliza la IP publica de salida de este equipo. Se consulta una sola vez."""
    with _LOCK:
        cached = _OWN_LOCATION_CACHE.get("self")
    if cached is not None:
        return cached
    result = _query("http://ip-api.com/json/?fields=status,country,regionName,city,isp")
    with _LOCK:
        _OWN_LOCATION_CACHE["self"] = result
    return result
