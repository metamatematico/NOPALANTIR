"""
Lista persistente de dispositivos de tu red, identificados por su
direccion MAC (no cambia aunque el DHCP les asigne otra IP). Permite
marcar cada uno como confiable, bloqueado, o dejarlo sin marcar.
"""

import csv
import os
import time
from typing import Dict

PATH = "known_devices.csv"
FIELDS = [
    "mac", "etiqueta", "fabricante", "tipo_probable",
    "ultimo_hostname", "ultima_ip", "primera_vez", "ultima_vez",
]

SIN_MARCAR = "Sin marcar"
CONFIABLE = "Confiable"
BLOQUEADO = "Bloqueado"


def load() -> Dict[str, dict]:
    if not os.path.exists(PATH):
        return {}
    with open(PATH, newline="", encoding="utf-8") as f:
        return {row["mac"]: row for row in csv.DictReader(f)}


def save_all(devices: Dict[str, dict]) -> None:
    with open(PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for mac, info in devices.items():
            writer.writerow({"mac": mac, **{k: info.get(k, "") for k in FIELDS if k != "mac"}})


def touch(mac: str, ip: str, hostname: str, fabricante: str = "", tipo_probable: str = "") -> str:
    """Registra/actualiza un dispositivo visto en un escaneo. Devuelve su etiqueta actual."""
    devices = load()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = devices.get(mac)
    if entry is None:
        entry = {"etiqueta": SIN_MARCAR, "primera_vez": now}
        devices[mac] = entry
    entry["ultimo_hostname"] = hostname or entry.get("ultimo_hostname", "")
    entry["ultima_ip"] = ip
    entry["ultima_vez"] = now
    if fabricante:
        entry["fabricante"] = fabricante
    if tipo_probable:
        entry["tipo_probable"] = tipo_probable
    save_all(devices)
    return entry["etiqueta"]


def mark(mac: str, etiqueta: str) -> None:
    devices = load()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = devices.setdefault(mac, {"primera_vez": now, "ultima_vez": now})
    entry["etiqueta"] = etiqueta
    save_all(devices)
