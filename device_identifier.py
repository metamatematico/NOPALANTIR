"""
Adivina fabricante y tipo de dispositivo a partir de su direccion MAC
(los primeros 3 bytes son el OUI, asignado por fabricante) y pistas en
su nombre de host. Es una suposicion razonable, no una certeza: la
tabla de fabricantes es parcial y los nombres de host los define cada
dispositivo, asi que pueden faltar o estar en blanco.
"""

_OUI_VENDORS = {
    "3c:e1:a1": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple", "dc:a9:04": "Apple",
    "ac:bc:32": "Apple", "00:1c:b3": "Apple", "f4:5c:89": "Apple", "d0:81:7a": "Apple",
    "f8:ff:c2": "Samsung", "5c:0a:5b": "Samsung", "8c:79:67": "Samsung", "ac:5f:3e": "Samsung",
    "e8:50:8b": "Xiaomi", "78:11:dc": "Xiaomi", "64:09:80": "Huawei", "00:e0:fc": "Huawei",
    "50:c7:bf": "TP-Link", "a4:2b:b0": "TP-Link", "c4:6e:1f": "TP-Link", "98:da:c4": "TP-Link",
    "00:14:6c": "D-Link", "ac:f1:df": "D-Link", "00:1f:33": "Netgear", "a0:40:a0": "Netgear",
    "04:bd:88": "Ubiquiti", "fc:ec:da": "Ubiquiti", "00:50:56": "VMware (virtual)",
    "08:00:27": "VirtualBox (virtual)", "00:15:5d": "Hyper-V (virtual)",
    "b8:27:eb": "Raspberry Pi Foundation", "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation", "fc:a1:83": "Amazon (Echo/Kindle/Fire)",
    "44:65:0d": "Amazon (Echo/Kindle/Fire)", "f0:27:2d": "Amazon (Echo/Kindle/Fire)",
    "f4:f5:d8": "Google (Nest/Chromecast)", "f4:f5:e8": "Google (Nest/Chromecast)",
    "00:1a:11": "Google", "3c:5a:b4": "Google", "00:1d:d8": "Microsoft",
    "00:50:f2": "Microsoft", "7c:1e:52": "Microsoft (Xbox)", "98:5f:d3": "Microsoft (Xbox)",
    "00:14:22": "Dell", "f8:bc:12": "Dell", "00:21:5c": "Dell", "9c:b6:54": "HP",
    "94:57:a5": "HP", "00:26:55": "Sony", "ac:9b:0a": "Sony (PlayStation)",
    "00:e0:91": "LG Electronics", "a0:39:f7": "LG Electronics",
    "24:0a:c4": "Espressif (ESP32/ESP8266 - IoT)", "ec:fa:bc": "Espressif (ESP32/ESP8266 - IoT)",
    "84:f3:eb": "Espressif (ESP32/ESP8266 - IoT)", "08:3a:f2": "Espressif (ESP32/ESP8266 - IoT)",
    "00:1b:63": "Cisco", "00:0c:29": "Cisco/VMware", "00:1e:c2": "Apple",
    "70:b3:d5": "ASUSTek", "1c:87:2c": "ASUSTek", "08:60:6e": "ASUSTek",
    "00:1d:0f": "Intel", "00:13:02": "Intel", "3c:97:0e": "Intel", "98:5a:eb": "Intel",
    "10:07:1d": "Router/equipo de red (ISP)",
}

_TYPE_HOST_HINTS = [
    ("Telefono/Tablet (iOS)", ["iphone", "ipad"]),
    ("Telefono/Tablet (Android)", ["android", "galaxy", "redmi", "huawei-", "honor-"]),
    ("Computadora (macOS)", ["macbook", "imac", "mac-"]),
    ("Computadora (Windows)", ["desktop-", "laptop-", "pc-"]),
    ("Consola de videojuegos", ["xbox", "playstation", "ps4", "ps5", "nintendo", "switch"]),
    ("Asistente/Altavoz inteligente", ["echo", "alexa", "google-home", "nest-"]),
    ("Television/Streaming", ["chromecast", "roku", "smarttv", "appletv", "firetv"]),
    ("Impresora", ["printer", "epson", "canon-", "hp-printer"]),
]


def _normalize_mac(mac: str) -> str:
    return mac.replace("-", ":").lower()


def guess_vendor(mac: str) -> str:
    if not mac or "desconocida" in mac.lower():
        return "Desconocido"
    norm = _normalize_mac(mac)
    prefix = norm[:8]
    return _OUI_VENDORS.get(prefix, "Desconocido")


def guess_device_type(vendor: str, hostname: str) -> str:
    hostname_l = (hostname or "").lower()
    for device_type, keywords in _TYPE_HOST_HINTS:
        for kw in keywords:
            if kw in hostname_l:
                return device_type

    if vendor.startswith("Router/equipo de red") or vendor in ("TP-Link", "D-Link", "Netgear", "Ubiquiti", "ASUSTek", "Cisco"):
        return "Probable router/equipo de red"
    if "virtual" in vendor.lower():
        return "Maquina virtual"
    if vendor == "Apple":
        return "Equipo Apple (iPhone/iPad/Mac - sin mas detalle)"
    if vendor == "Samsung" or vendor == "Xiaomi" or vendor == "Huawei":
        return "Probable telefono/tablet Android"
    if "Raspberry Pi" in vendor:
        return "Raspberry Pi / proyecto IoT"
    if "Amazon" in vendor:
        return "Dispositivo Amazon (Echo/Kindle/Fire TV)"
    if "Google" in vendor:
        return "Dispositivo Google (Nest/Chromecast/Android)"
    if "Espressif" in vendor:
        return "Dispositivo IoT (microcontrolador WiFi)"
    if vendor in ("Dell", "HP", "Intel", "Microsoft"):
        return "Probable computadora (Windows)"
    if vendor == "Sony":
        return "Equipo Sony (posible PlayStation/TV)"
    return "Desconocido"


def describe(mac: str, hostname: str) -> "tuple[str, str]":
    """Devuelve (fabricante, tipo_probable) para mostrar al usuario."""
    vendor = guess_vendor(mac)
    device_type = guess_device_type(vendor, hostname)
    return vendor, device_type
