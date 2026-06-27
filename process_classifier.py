"""
Clasificador heuristico de procesos por tipo de uso de red.
Usado por monitor_core para agrupar las conexiones activas por
categoria de programa (navegador, mensajeria, sistema, etc.).
"""

_CATEGORY_KEYWORDS = [
    ("Navegador web", ["chrome", "firefox", "msedge", "edge", "opera", "brave", "iexplore", "vivaldi"]),
    ("Mensajeria/Videollamadas", ["discord", "slack", "teams", "zoom", "skype", "whatsapp", "telegram", "webex"]),
    ("Nube/Sincronizacion", ["onedrive", "dropbox", "googledrive", "drive", "icloud", "backup"]),
    ("Juegos", ["steam", "epicgameslauncher", "riotclient", "battle.net", "origin", "ubisoftconnect"]),
    ("Multimedia/Streaming", ["spotify", "vlc", "netflix", "itunes", "applemusic"]),
    ("Descargas/Torrent", ["utorrent", "bittorrent", "qbittorrent", "transmission"]),
    ("Seguridad/Antivirus", ["msmpeng", "avast", "avg", "norton", "mcafee", "defender", "windefend"]),
    ("Actualizaciones", ["wuauclt", "updater", "update", "setup"]),
    ("Desarrollo/Herramientas", ["python", "pythonw", "node", "java", "code", "docker"]),
    ("Sistema operativo", ["svchost", "system", "wininit", "services", "lsass", "csrss", "explorer",
                            "registry", "smss", "winlogon", "spoolsv", "dwm", "dllhost"]),
]


def classify_process(name: str) -> str:
    if not name or name == "?":
        return "Desconocido"
    lname = name.lower().replace(".exe", "")
    for category, keywords in _CATEGORY_KEYWORDS:
        for kw in keywords:
            if kw in lname:
                return category
    return "Otro"
