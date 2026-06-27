"""
Bloquea/desbloquea una IP en el Firewall de Windows para que no pueda
comunicarse con ESTE equipo. Requiere permisos de administrador; sin
ellos, la regla no se aplica y se informa al usuario. No afecta al
resto de la red ni al router -- eso requiere la configuracion del
router, fuera del alcance de esta aplicacion.
"""

import subprocess

_NO_WINDOW = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=10, creationflags=_NO_WINDOW)


def block_ip(ip: str):
    base = f"Monitor-Bloqueo-{ip}"
    try:
        r_in = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={base}-in", "dir=in", "action=block", f"remoteip={ip}",
        ])
        r_out = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={base}-out", "dir=out", "action=block", f"remoteip={ip}",
        ])
        if r_in.returncode == 0 and r_out.returncode == 0:
            return True, "Bloqueado en este equipo (entrante y saliente)."
        detail = (r_in.stderr or r_in.stdout or r_out.stderr or r_out.stdout).strip()
        return False, detail or "No se pudo crear la regla. ¿Ejecutaste la app como administrador?"
    except Exception as exc:
        return False, str(exc)


def unblock_ip(ip: str):
    base = f"Monitor-Bloqueo-{ip}"
    try:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={base}-in"])
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={base}-out"])
        return True, "Reglas eliminadas (si existian)."
    except Exception as exc:
        return False, str(exc)
