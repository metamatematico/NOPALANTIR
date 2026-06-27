"""
Traduce puertos remotos comunes a una descripcion legible, como
indicio de que tipo de actividad/protocolo es (no del contenido real).
"""

_KNOWN_PORTS = {
    20: "FTP (datos)", 21: "FTP (control)", 22: "SSH/SFTP", 23: "Telnet",
    25: "SMTP (correo saliente)", 53: "DNS", 80: "HTTP (web sin cifrar)",
    110: "POP3 (correo)", 119: "NNTP", 123: "NTP (hora)",
    139: "NetBIOS (carpetas compartidas)", 143: "IMAP (correo)",
    443: "HTTPS (web cifrada)", 445: "SMB (carpetas compartidas)",
    465: "SMTP seguro", 587: "SMTP seguro", 993: "IMAP seguro",
    995: "POP3 seguro", 1433: "SQL Server", 3306: "MySQL",
    3389: "RDP (escritorio remoto)", 5432: "PostgreSQL", 5900: "VNC (escritorio remoto)",
}


def guess_protocol(port: int) -> str:
    if not port:
        return "Desconocido"
    return _KNOWN_PORTS.get(port, f"Puerto {port}")
