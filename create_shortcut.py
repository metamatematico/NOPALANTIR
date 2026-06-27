"""
Utilidad para crear un acceso directo en el Escritorio que abre el
prototipo (Agente 3) sin mostrar consola, usando pythonw.exe.
"""

import os
import subprocess
import sys


def _find_pythonw() -> str:
    candidate = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return candidate if os.path.exists(candidate) else sys.executable


def create_desktop_shortcut(app_path: str, shortcut_name: str = "Monitor de Trafico de Red") -> str:
    pythonw = _find_pythonw()
    app_path = os.path.abspath(app_path)
    project_dir = os.path.dirname(app_path)
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    shortcut_path = os.path.join(desktop, f"{shortcut_name}.lnk")

    ps_script = (
        "$ws = New-Object -ComObject WScript.Shell;"
        f"$s = $ws.CreateShortcut('{shortcut_path}');"
        f"$s.TargetPath = '{pythonw}';"
        f"$s.Arguments = '\"{app_path}\"';"
        f"$s.WorkingDirectory = '{project_dir}';"
        f"$s.IconLocation = '{pythonw}';"
        "$s.Description = 'Prototipo de monitoreo de trafico de red';"
        "$s.Save()"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        check=True,
        capture_output=True,
        text=True,
    )
    return shortcut_path
