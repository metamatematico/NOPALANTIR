"""
Escanea la red local (no Internet) para listar TODOS los dispositivos
que responden en la misma red que este equipo -- no solo los que ya
se conectaron a un proceso de esta maquina. Combina un sondeo activo
(ping + puertos comunes) con la tabla ARP del sistema operativo.

Es una accion activa (envia trafico a cada IP de tu subred), por eso
se ejecuta solo a peticion explicita, nunca automaticamente cada 2s.
"""

import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Optional

import psutil

COMMON_PORTS = (80, 443, 445, 139, 22, 3389, 8080, 8443)
PING_TIMEOUT_MS = 300
TCP_TIMEOUT_SECONDS = 0.3
MAX_HOSTS_TO_SCAN = 512

_NO_WINDOW = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


@dataclass
class LanHost:
    ip: str
    mac: str


def _own_ipv4_addrs() -> set:
    own = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family.name == "AF_INET":
                own.add(a.address)
    return own


def _local_subnet() -> Optional[ipaddress.IPv4Network]:
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family.name != "AF_INET" or not a.address or a.address.startswith("127."):
                continue
            try:
                net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
            except (ValueError, TypeError):
                continue
            if net.is_private and 2 < net.num_addresses - 2 <= MAX_HOSTS_TO_SCAN:
                return net
    return None


def _tcp_alive(ip: str) -> bool:
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=TCP_TIMEOUT_SECONDS):
                return True
        except OSError:
            continue
    return False


def _ping(ip: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip],
            capture_output=True, timeout=2, creationflags=_NO_WINDOW,
        )
        return result.returncode == 0
    except Exception:
        return False


_INVALID_MACS = {"ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00"}


def _stimulate(ip: str) -> None:
    # El resultado de ping/TCP no se usa para decidir si el host esta
    # "vivo": algunos routers de ISP responden o interceptan trafico
    # hacia IPs que nadie esta usando, lo que da falsos positivos
    # masivos. Solo se usa para forzar que el sistema resuelva ARP.
    if not _tcp_alive(ip):
        _ping(ip)


def _read_arp_table() -> Dict[str, str]:
    mapping = {}
    try:
        output = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5, creationflags=_NO_WINDOW,
        ).stdout
    except Exception:
        return mapping
    for line in output.splitlines():
        match = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
        if not match:
            continue
        ip, mac, _kind = match.groups()
        mac = mac.lower()
        if mac in _INVALID_MACS:
            continue
        mapping[ip] = mac
    return mapping


def scan_network() -> List[LanHost]:
    """Sondeo activo de la subred local. Puede tardar varios segundos.

    La fuente de verdad de "quien esta conectado" es la tabla ARP real
    del sistema operativo (solo se llena con dispositivos que de hecho
    respondieron a nivel de red local). El ping/TCP solo se usa para
    estimular esas respuestas, no para decidir si un host existe.
    """
    network = _local_subnet()
    if network is None:
        return []
    own_ips = _own_ipv4_addrs()
    candidates = [str(ip) for ip in network.hosts() if str(ip) not in own_ips]

    with ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(_stimulate, candidates))

    arp_table = _read_arp_table()
    excluded = own_ips | {str(network.network_address), str(network.broadcast_address)}
    hosts = []
    for ip, mac in sorted(arp_table.items()):
        if ip in excluded or mac.startswith(("01-00-5e", "33-33-")):
            continue
        try:
            if ipaddress.ip_address(ip).is_multicast:
                continue
        except ValueError:
            continue
        hosts.append(LanHost(ip=ip, mac=mac))
    return hosts
