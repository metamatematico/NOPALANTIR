"""
Agente 3 - Generador de Codigo.

Construye el prototipo de interfaz grafica a partir del flujo de
trabajo definido por el Agente 2. Al ejecutarse SOLO abre la ventana
de control: el monitoreo no arranca solo, el usuario lo activa con el
boton "Iniciar monitoreo".
"""

import os
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import device_identifier
import firewall_blocker
import geo_lookup
import hostname_lookup
import known_devices
import lan_scanner
from create_shortcut import create_desktop_shortcut
from flow_architect import build_workflow
from monitor_core import Snapshot, TrafficMonitor
from process_blocker import terminate_unknown
from process_inspector import inspect_process
from requirements_agent import define_requirements

APP_TITLE = "Monitor de Trafico de Red"


class MonitorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1180x700")
        self.root.minsize(900, 580)

        self.requirements = define_requirements()
        self.workflow = build_workflow(self.requirements)
        self.monitor = TrafficMonitor(self.workflow)

        self._snapshot_queue: "queue.Queue[Snapshot]" = queue.Queue()
        self._stop_event = threading.Event()
        self._worker = None
        self._running = False
        self._latest_connections = []
        self._alert_blinking = False
        self._alert_blink_on = False
        self._attack_popup_shown = set()
        self._own_location_requested = False
        self.own_location_var = tk.StringVar(
            value="Tu ubicacion aproximada: (se detecta al iniciar el monitoreo)"
        )

        self._lan_scan_queue: "queue.Queue[list]" = queue.Queue()
        self._lan_scan_in_progress = False
        self._lan_popup_shown = set()
        self.lan_scan_status_var = tk.StringVar(value="Aun no se ha escaneado la red.")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- UI ----------
    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text=APP_TITLE, font=("Segoe UI", 14, "bold")).pack(side="left")
        self.status_var = tk.StringVar(value="Detenido")
        ttk.Label(top, textvariable=self.status_var, foreground="#a33").pack(side="right")

        self.alert_banner_var = tk.StringVar(value="")
        ttk.Label(
            top, textvariable=self.alert_banner_var, font=("Segoe UI", 11, "bold"), foreground="#cc0000",
        ).pack(side="right", padx=(0, 14))
        self.alert_indicator = tk.Label(
            top, text="●", font=("Segoe UI", 16, "bold"), fg="#bbbbbb",
        )
        self.alert_indicator.pack(side="right", padx=(0, 6))

        controls = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        controls.pack(fill="x")
        self.start_btn = ttk.Button(controls, text="Iniciar monitoreo", command=self.start_monitoring)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(controls, text="Detener", command=self.stop_monitoring, state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))
        self.shortcut_btn = ttk.Button(
            controls, text="Crear acceso directo en el Escritorio", command=self.make_shortcut
        )
        self.shortcut_btn.pack(side="right")

        info = (
            f"Intervalo: {self.requirements.refresh_interval_seconds:.0f}s   "
            f"Umbral de trafico: {self.requirements.bandwidth_alert_mbps:.0f} Mbps   "
            f"Umbral de conexiones: {self.requirements.connection_count_alert}   "
            f"Log: {self.requirements.log_path if self.requirements.log_to_file else 'desactivado'}"
        )
        ttk.Label(self.root, text=info, padding=(10, 0), foreground="#555").pack(fill="x")

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self._build_summary_tab(notebook)
        self._build_connections_tab(notebook)
        self._build_devices_tab(notebook)
        self._build_egress_tab(notebook)
        self._build_attacks_tab(notebook)
        self._build_lan_devices_tab(notebook)

    def _build_summary_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Resumen")

        ttk.Label(tab, textvariable=self.own_location_var, foreground="#555", padding=(4, 0, 4, 6)).pack(fill="x")

        paned = ttk.PanedWindow(tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        iface_frame = ttk.LabelFrame(paned, text="Interfaces de red")
        self.iface_tree = ttk.Treeview(
            iface_frame, columns=("subida", "bajada", "enviado", "recibido"), show="tree headings", height=8
        )
        self.iface_tree.heading("#0", text="Interfaz")
        self.iface_tree.column("#0", width=160, anchor="w")
        for col, label, width in [
            ("subida", "Subida (Mbps)", 100),
            ("bajada", "Bajada (Mbps)", 100),
            ("enviado", "Enviado (bytes)", 130),
            ("recibido", "Recibido (bytes)", 130),
        ]:
            self.iface_tree.heading(col, text=label)
            self.iface_tree.column(col, width=width, anchor="e")
        self.iface_tree.pack(fill="both", expand=True)
        paned.add(iface_frame, weight=3)

        cat_frame = ttk.LabelFrame(paned, text="Programas por tipo (conexiones activas)")
        self.category_tree = ttk.Treeview(cat_frame, columns=("conexiones",), show="tree headings", height=8)
        self.category_tree.heading("#0", text="Tipo de programa")
        self.category_tree.column("#0", width=200, anchor="w")
        self.category_tree.heading("conexiones", text="Conexiones")
        self.category_tree.column("conexiones", width=90, anchor="e")
        self.category_tree.pack(fill="both", expand=True)
        self.category_tree.bind("<<TreeviewSelect>>", self._on_category_select)
        ttk.Label(
            cat_frame, text="Clic en un tipo para ver que procesos lo componen.",
            foreground="#777",
        ).pack(fill="x", pady=(2, 0))
        paned.add(cat_frame, weight=2)

        alert_frame = ttk.LabelFrame(tab, text="Alertas")
        self.alert_text = tk.Text(alert_frame, height=6, state="disabled", wrap="word")
        self.alert_text.pack(fill="both", expand=True)
        alert_frame.pack(fill="x", padx=4, pady=(0, 4))

    def _build_connections_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Conexiones activas")

        switch_bar = ttk.Frame(tab, padding=(4, 4, 4, 0))
        switch_bar.pack(fill="x")
        self.block_unknown_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            switch_bar, text="Cerrar procesos \"Desconocido\" detectados ahora",
            variable=self.block_unknown_var, command=self._on_block_unknown_toggle,
        ).pack(side="left")
        ttk.Label(
            switch_bar, foreground="#777",
            text="Accion puntual e irreversible: cierra solo lo que esta en pantalla en este momento.",
        ).pack(side="left", padx=(10, 0))

        self.conn_tree = ttk.Treeview(
            tab, columns=("pid", "proceso", "tipo", "local", "remoto", "origen", "ubicacion", "estado"),
            show="headings",
        )
        for col, label, width in [
            ("pid", "PID", 55),
            ("proceso", "Proceso", 120),
            ("tipo", "Tipo de programa", 150),
            ("local", "Direccion local", 140),
            ("remoto", "Direccion remota", 140),
            ("origen", "Origen", 170),
            ("ubicacion", "Ubicacion / ISP", 230),
            ("estado", "Estado", 80),
        ]:
            self.conn_tree.heading(col, text=label)
            self.conn_tree.column(col, width=width, anchor="w")
        self.conn_tree.pack(fill="both", expand=True, padx=4, pady=4)

    def _build_devices_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Otros dispositivos en mi red")

        ttk.Label(
            tab,
            text=(
                "Equipos distintos al tuyo (direcciones IP privadas de tu red local) que han "
                "establecido conexion con procesos de este equipo. No incluye servidores de "
                "Internet ni a este mismo equipo."
            ),
            wraplength=950, justify="left", padding=8, foreground="#555",
        ).pack(fill="x")

        self.device_tree = ttk.Treeview(
            tab, columns=("hostname", "conexiones", "procesos", "primera_vez", "ultima_vez"), show="tree headings",
        )
        self.device_tree.heading("#0", text="Direccion IP")
        self.device_tree.column("#0", width=140, anchor="w")
        for col, label, width in [
            ("hostname", "Nombre de host", 180),
            ("conexiones", "Conexiones", 90),
            ("procesos", "Procesos locales involucrados", 260),
            ("primera_vez", "Primera vez visto", 120),
            ("ultima_vez", "Ultima vez visto", 120),
        ]:
            self.device_tree.heading(col, text=label)
            self.device_tree.column(col, width=width, anchor="w")
        self.device_tree.pack(fill="both", expand=True, padx=4, pady=4)

    def _build_egress_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Quien extrae tus datos")

        ttk.Label(
            tab, wraplength=1100, justify="left", foreground="#555", padding=8,
            text=(
                "Cada conexion establecida con un sistema externo (Internet o tu red local) queda "
                "registrada aqui: quien (proceso), cuando empezo y termino, desde que punto del mundo "
                "se conecta, que protocolo/puerto usa, y un volumen ESTIMADO de datos. La estimacion "
                "reparte el trafico total de tu tarjeta de red entre las conexiones activas en cada "
                "instante, asi que es aproximada, no exacta. Por las mismas limitaciones tecnicas (y "
                "porque la mayoria del trafico va cifrado con HTTPS), no es posible ver el contenido "
                "real de lo transmitido. Todo el historial tambien se guarda en "
                f"{self.requirements.egress_log_path} para consulta posterior, incluso si cierras la app."
            ),
        ).pack(fill="x")

        action_bar = ttk.Frame(tab, padding=(8, 0, 8, 4))
        action_bar.pack(fill="x")
        ttk.Label(
            action_bar, foreground="#555",
            text="Si no reconoces un destino, selecciona su fila (Ctrl+clic para varias) y:",
        ).pack(side="left")
        ttk.Button(
            action_bar, text="Cerrar proceso(s) de la(s) conexion(es) seleccionada(s)",
            command=lambda: self._close_selected_processes(self.egress_tree),
        ).pack(side="left", padx=(8, 0))

        container = ttk.Frame(tab)
        container.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        vsb = ttk.Scrollbar(container, orient="vertical")
        hsb = ttk.Scrollbar(container, orient="horizontal")
        self.egress_tree = ttk.Treeview(
            container,
            columns=("pid", "inicio", "fin", "duracion", "proceso", "categoria", "destino",
                     "protocolo", "origen", "ubicacion", "volumen", "estado"),
            show="headings", yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        for col, label, width in [
            ("pid", "PID", 55), ("inicio", "Inicio", 130), ("fin", "Ultima actividad", 130),
            ("duracion", "Duracion", 70), ("proceso", "Proceso", 110), ("categoria", "Tipo", 130),
            ("destino", "Destino", 150), ("protocolo", "Protocolo", 170), ("origen", "Origen", 170),
            ("ubicacion", "Ubicacion / ISP", 220), ("volumen", "Volumen aprox.", 100), ("estado", "Estado", 90),
        ]:
            self.egress_tree.heading(col, text=label)
            self.egress_tree.column(col, width=width, anchor="w")
        vsb.config(command=self.egress_tree.yview)
        hsb.config(command=self.egress_tree.xview)
        self.egress_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

    def _build_attacks_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Posibles ataques")

        ttk.Label(
            tab, wraplength=1100, justify="left", foreground="#555", padding=8,
            text=(
                "Detecta dos patrones clasicos: escaneo de puertos (la misma IP toca muchos "
                f"puertos distintos de tu equipo en {self.requirements.attack_window_seconds}s) y "
                "posible fuerza bruta (muchos intentos repetidos contra el mismo puerto sensible: "
                "RDP, SSH, carpetas compartidas, bases de datos, VNC, etc.). Solo se detecta lo que "
                "realmente llega a crear una conexion en el sistema operativo -- la mayoria de "
                "escaneos de Internet ya los bloquea el Firewall de Windows antes de llegar aqui, "
                "asi que esto es mas util para abuso de algo que tienes expuesto o ataques desde tu "
                "propia red local. Cada deteccion tambien se guarda en "
                f"{self.requirements.attack_log_path}."
            ),
        ).pack(fill="x")

        action_bar = ttk.Frame(tab, padding=(8, 0, 8, 4))
        action_bar.pack(fill="x")
        ttk.Label(
            action_bar, foreground="#555",
            text="Si quieres dejar de exponer el servicio atacado, selecciona la fila y:",
        ).pack(side="left")
        ttk.Button(
            action_bar, text="Cerrar proceso local expuesto",
            command=lambda: self._close_selected_processes(self.attack_tree),
        ).pack(side="left", padx=(8, 0))

        container = ttk.Frame(tab)
        container.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        vsb = ttk.Scrollbar(container, orient="vertical")
        hsb = ttk.Scrollbar(container, orient="horizontal")
        self.attack_tree = ttk.Treeview(
            container,
            columns=("pid", "tipo", "origen_ip", "ubicacion", "proceso_local",
                     "detalle", "primera", "ultima", "veces"),
            show="headings", yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        for col, label, width in [
            ("pid", "PID local", 70), ("tipo", "Tipo", 150), ("origen_ip", "IP de origen", 140),
            ("ubicacion", "Ubicacion / ISP", 200), ("proceso_local", "Proceso local expuesto", 160),
            ("detalle", "Detalle", 320), ("primera", "Primera deteccion", 130),
            ("ultima", "Ultima actividad", 130), ("veces", "Veces", 60),
        ]:
            self.attack_tree.heading(col, text=label)
            self.attack_tree.column(col, width=width, anchor="w")
        vsb.config(command=self.attack_tree.yview)
        hsb.config(command=self.attack_tree.xview)
        self.attack_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

    def _build_lan_devices_tab(self, notebook: ttk.Notebook):
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Quien esta en mi red")

        ttk.Label(
            tab, wraplength=1100, justify="left", foreground="#555", padding=8,
            text=(
                "Lista TODO lo que responde en tu red local en este momento, no solo lo que se "
                "conecto con este equipo -- util para detectar a alguien ajeno usando tu Internet. "
                "Es un escaneo activo (envia trafico a tu subred), por eso es manual o cada 90s "
                "mientras el monitoreo esta activo, no cada 2s. Cada dispositivo se identifica por "
                "su direccion MAC. \"Bloquear\" solo evita que ese dispositivo se comunique con ESTE "
                "equipo (regla de Firewall de Windows, requiere ejecutar como administrador); no lo "
                "expulsa de tu WiFi/router -- eso solo se hace desde la configuracion del router. "
                "El fabricante y tipo probable son una suposicion a partir de la MAC y el nombre de "
                "host (no una certeza): no hay forma de saber con 100% de seguridad si es un telefono "
                "o que sistema operativo usa sin acceder al propio dispositivo."
            ),
        ).pack(fill="x")

        controls_bar = ttk.Frame(tab, padding=(8, 0, 8, 4))
        controls_bar.pack(fill="x")
        self.lan_scan_btn = ttk.Button(
            controls_bar, text="Escanear red ahora", command=self._trigger_lan_scan,
        )
        self.lan_scan_btn.pack(side="left")
        ttk.Label(controls_bar, textvariable=self.lan_scan_status_var, foreground="#555").pack(
            side="left", padx=(10, 0)
        )

        action_bar = ttk.Frame(tab, padding=(8, 0, 8, 4))
        action_bar.pack(fill="x")
        ttk.Label(action_bar, foreground="#555", text="Selecciona uno o varios y:").pack(side="left")
        ttk.Button(
            action_bar, text="Marcar como confiable",
            command=lambda: self._mark_lan_devices(known_devices.CONFIABLE),
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            action_bar, text="Bloquear en mi equipo",
            command=lambda: self._mark_lan_devices(known_devices.BLOQUEADO),
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            action_bar, text="Quitar marca/bloqueo",
            command=lambda: self._mark_lan_devices(known_devices.SIN_MARCAR),
        ).pack(side="left", padx=(8, 0))

        container = ttk.Frame(tab)
        container.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        vsb = ttk.Scrollbar(container, orient="vertical")
        hsb = ttk.Scrollbar(container, orient="horizontal")
        self.lan_tree = ttk.Treeview(
            container, columns=("mac", "ip", "hostname", "fabricante", "tipo", "etiqueta"),
            show="headings", yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        for col, label, width in [
            ("mac", "MAC", 150), ("ip", "IP", 120), ("hostname", "Nombre de host", 180),
            ("fabricante", "Fabricante (por MAC)", 170), ("tipo", "Tipo probable", 220),
            ("etiqueta", "Estado", 110),
        ]:
            self.lan_tree.heading(col, text=label)
            self.lan_tree.column(col, width=width, anchor="w")
        vsb.config(command=self.lan_tree.yview)
        hsb.config(command=self.lan_tree.xview)
        self.lan_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

    # ---------- Acciones ----------
    def start_monitoring(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._attack_popup_shown = set()
        self.status_var.set("Monitoreando...")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._worker = threading.Thread(target=self._poll_loop, daemon=True)
        self._worker.start()
        self.root.after(200, self._drain_queue)
        self._lan_popup_shown = set()
        self._trigger_lan_scan()
        self.root.after(90000, self._auto_scan_tick)
        if not self._own_location_requested:
            self._own_location_requested = True
            self.own_location_var.set("Tu ubicacion aproximada: detectando...")
            self._location_queue: "queue.Queue[str]" = queue.Queue()
            threading.Thread(target=self._fetch_own_location, daemon=True).start()
            self.root.after(300, self._poll_location_queue)

    def _fetch_own_location(self):
        info = geo_lookup.get_own_location()
        if info == geo_lookup.ERROR:
            text = "Tu ubicacion aproximada: no disponible (revisa tu conexion a Internet)."
        else:
            text = f"Tu conexion sale aproximadamente desde: {info.label()} — ISP: {info.isp or 'desconocido'}"
        self._location_queue.put(text)

    def _poll_location_queue(self):
        try:
            text = self._location_queue.get_nowait()
            self.own_location_var.set(text)
        except queue.Empty:
            self.root.after(300, self._poll_location_queue)

    def stop_monitoring(self):
        self._running = False
        self._stop_event.set()
        self.status_var.set("Detenido")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self._stop_alert_blink()

    # ---------- Indicador visual de alertas ----------
    def _start_alert_blink(self):
        if self._alert_blinking:
            return
        self._alert_blinking = True
        self._alert_blink_on = True
        self.alert_banner_var.set("¡ALERTA!")
        self._alert_blink_step()

    def _alert_blink_step(self):
        if not self._alert_blinking:
            return
        self.alert_indicator.config(fg="#ff2222" if self._alert_blink_on else "#660000")
        self._alert_blink_on = not self._alert_blink_on
        self.root.after(450, self._alert_blink_step)

    def _stop_alert_blink(self):
        self._alert_blinking = False
        self.alert_indicator.config(fg="#bbbbbb")
        self.alert_banner_var.set("")

    def make_shortcut(self):
        try:
            app_path = os.path.abspath(__file__)
            path = create_desktop_shortcut(app_path)
            messagebox.showinfo(APP_TITLE, f"Acceso directo creado:\n{path}")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"No se pudo crear el acceso directo:\n{exc}")

    # ---------- Ventana emergente al detectar un ataque ----------
    def _show_attack_popup(self, event):
        win = tk.Toplevel(self.root)
        win.title("¡Posible ataque detectado!")
        win.geometry("520x340")
        win.resizable(False, False)
        win.transient(self.root)
        win.attributes("-topmost", True)
        self.root.bell()

        ttk.Label(
            win, text=f"⚠ {event.kind}", font=("Segoe UI", 13, "bold"), foreground="#cc0000",
        ).pack(pady=(14, 6))

        ubicacion = event.location if event.isp in ("-", event.location) else f"{event.location} — {event.isp}"
        rows = [
            ("IP de origen", event.source_ip),
            ("Ubicacion", ubicacion),
            ("Proceso local expuesto", f"{event.local_process} (PID {event.local_pid})" if event.local_pid else event.local_process),
            ("Detalle", event.detail),
            ("Primera deteccion", event.first_seen),
            ("Veces detectado", str(event.hit_count)),
        ]
        body = ttk.Frame(win, padding=(20, 0))
        body.pack(fill="both", expand=True)
        for i, (label, value) in enumerate(rows):
            ttk.Label(body, text=f"{label}:", font=("Segoe UI", 9, "bold")).grid(
                row=i, column=0, sticky="ne", padx=(0, 8), pady=3
            )
            ttk.Label(body, text=value, wraplength=340, justify="left").grid(
                row=i, column=1, sticky="nw", pady=3
            )

        def on_block():
            if not event.local_pid:
                messagebox.showinfo(APP_TITLE, "No hay un proceso local identificado para cerrar.", parent=win)
                win.destroy()
                return
            results = terminate_unknown([event.local_pid])
            r = results[0]
            messagebox.showinfo(
                APP_TITLE,
                f"PID {r.pid} ({r.name}): {'Cerrado' if r.success else 'No se pudo cerrar'} — {r.detail}",
                parent=win,
            )
            win.destroy()

        btn_bar = ttk.Frame(win, padding=16)
        btn_bar.pack(fill="x")
        ttk.Button(btn_bar, text="Bloquear ahora (cerrar proceso)", command=on_block).pack(side="left")
        ttk.Button(btn_bar, text="Ignorar", command=win.destroy).pack(side="right")

        win.grab_set()

    # ---------- Escaneo de "quien esta en mi red" ----------
    def _auto_scan_tick(self):
        if not self._running:
            return
        self._trigger_lan_scan()
        self.root.after(90000, self._auto_scan_tick)

    def _trigger_lan_scan(self):
        if self._lan_scan_in_progress:
            return
        self._lan_scan_in_progress = True
        self.lan_scan_status_var.set("Escaneando tu red... (puede tardar varios segundos)")
        self.lan_scan_btn.config(state="disabled")
        threading.Thread(target=self._run_lan_scan, daemon=True).start()
        self.root.after(300, self._poll_lan_scan_queue)

    def _run_lan_scan(self):
        hosts = lan_scanner.scan_network()
        self._lan_scan_queue.put(hosts)

    def _poll_lan_scan_queue(self):
        try:
            hosts = self._lan_scan_queue.get_nowait()
        except queue.Empty:
            self.root.after(300, self._poll_lan_scan_queue)
            return
        self._lan_scan_in_progress = False
        self.lan_scan_btn.config(state="normal")
        self.lan_scan_status_var.set(
            f"Ultimo escaneo: {time.strftime('%H:%M:%S')} — {len(hosts)} dispositivo(s) encontrados"
        )
        self._render_lan_devices(hosts)

    def _render_lan_devices(self, hosts):
        self.lan_tree.delete(*self.lan_tree.get_children())
        unrecognized = []
        for host in hosts:
            hostname_lookup.request_lookup(host.ip)
            hostname = hostname_lookup.get_cached(host.ip)
            if hostname is None or hostname == hostname_lookup.PENDING:
                hostname = "Buscando..."
            fabricante, tipo_probable = device_identifier.describe(host.mac, hostname)
            etiqueta = known_devices.touch(host.mac, host.ip, hostname, fabricante, tipo_probable)
            self.lan_tree.insert(
                "", "end", values=(host.mac, host.ip, hostname, fabricante, tipo_probable, etiqueta)
            )
            if etiqueta == known_devices.SIN_MARCAR:
                unrecognized.append((host.mac, host.ip, hostname, fabricante, tipo_probable))

        if unrecognized:
            self._start_alert_blink()
            for mac, ip, hostname, fabricante, tipo_probable in unrecognized:
                if mac not in self._lan_popup_shown:
                    self._lan_popup_shown.add(mac)
                    self._show_unrecognized_device_popup(mac, ip, hostname, fabricante, tipo_probable)

    def _mark_lan_devices(self, etiqueta: str):
        selection = self.lan_tree.selection()
        if not selection:
            messagebox.showinfo(APP_TITLE, "Selecciona uno o mas dispositivos de la lista.")
            return
        for item in selection:
            mac, ip = self.lan_tree.item(item, "values")[:2]
            known_devices.mark(mac, etiqueta)
            if etiqueta == known_devices.BLOQUEADO:
                ok, msg = firewall_blocker.block_ip(ip)
                messagebox.showinfo(APP_TITLE, f"{ip}: {msg}")
            else:
                firewall_blocker.unblock_ip(ip)
            values = list(self.lan_tree.item(item, "values"))
            values[5] = etiqueta
            self.lan_tree.item(item, values=values)

    def _show_unrecognized_device_popup(self, mac: str, ip: str, hostname: str, fabricante: str, tipo_probable: str):
        win = tk.Toplevel(self.root)
        win.title("Dispositivo no reconocido en tu red")
        win.geometry("480x320")
        win.resizable(False, False)
        win.transient(self.root)
        win.attributes("-topmost", True)
        self.root.bell()

        ttk.Label(
            win, text="⚠ Dispositivo no reconocido en tu red", font=("Segoe UI", 12, "bold"),
            foreground="#cc0000", wraplength=440, justify="left",
        ).pack(pady=(14, 6), padx=14)

        body = ttk.Frame(win, padding=(20, 0))
        body.pack(fill="both", expand=True)
        rows = [
            ("MAC", mac), ("IP", ip), ("Nombre de host", hostname),
            ("Fabricante (por MAC)", fabricante), ("Tipo probable", tipo_probable),
        ]
        for i, (label, value) in enumerate(rows):
            ttk.Label(body, text=f"{label}:", font=("Segoe UI", 9, "bold")).grid(
                row=i, column=0, sticky="ne", padx=(0, 8), pady=3
            )
            ttk.Label(body, text=value, wraplength=320, justify="left").grid(
                row=i, column=1, sticky="nw", pady=3
            )

        def respond(etiqueta):
            known_devices.mark(mac, etiqueta)
            if etiqueta == known_devices.BLOQUEADO:
                ok, msg = firewall_blocker.block_ip(ip)
                messagebox.showinfo(APP_TITLE, f"{ip}: {msg}", parent=win)
            win.destroy()

        btn_bar = ttk.Frame(win, padding=16)
        btn_bar.pack(fill="x")
        ttk.Button(btn_bar, text="Es mio, confiable", command=lambda: respond(known_devices.CONFIABLE)).pack(side="left")
        ttk.Button(btn_bar, text="Bloquear en mi equipo", command=lambda: respond(known_devices.BLOQUEADO)).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(btn_bar, text="Ignorar por ahora", command=win.destroy).pack(side="right")

        win.grab_set()

    # ---------- Switch: cerrar procesos "Desconocido" ----------
    def _on_block_unknown_toggle(self):
        if not self.block_unknown_var.get():
            return  # se desactivo manualmente, no hay accion que revertir

        unique_pids = sorted({c.pid for c in self._latest_connections if c.category == "Desconocido" and c.pid})
        if not unique_pids:
            messagebox.showinfo(APP_TITLE, "No hay procesos clasificados como \"Desconocido\" en este momento.")
            self.block_unknown_var.set(False)
            return

        proceed = messagebox.askyesno(
            APP_TITLE,
            f"Esto va a cerrar {len(unique_pids)} proceso(s) clasificados como \"Desconocido\" "
            f"(PID: {', '.join(map(str, unique_pids))}).\n\n"
            "Esta accion es irreversible. ¿Continuar?",
        )
        if not proceed:
            self.block_unknown_var.set(False)
            return

        results = terminate_unknown(unique_pids)
        resumen = "\n".join(
            f"PID {r.pid} ({r.name}): {'Cerrado' if r.success else 'No se pudo cerrar'} — {r.detail}"
            for r in results
        )
        messagebox.showinfo(APP_TITLE, f"Resultado:\n\n{resumen}")
        self.block_unknown_var.set(False)

    # ---------- Detalle por categoria y por proceso ----------
    def _on_category_select(self, _event):
        selection = self.category_tree.selection()
        if not selection:
            return
        category = self.category_tree.item(selection[0], "text")
        self._show_category_detail(category)

    def _show_category_detail(self, category: str):
        matches = [c for c in self._latest_connections if c.category == category]

        win = tk.Toplevel(self.root)
        win.title(f"Detalle: {category}")
        win.geometry("900x380")

        if not matches:
            ttk.Label(
                win, padding=12,
                text="Sin datos todavia. Inicia el monitoreo o espera a la siguiente lectura.",
            ).pack()
            return

        ttk.Label(
            win, padding=8,
            text=f"{len(matches)} conexion(es) clasificada(s) como \"{category}\". "
                 f"Doble clic en una fila para ver toda la informacion del proceso.",
        ).pack(fill="x")

        action_bar = ttk.Frame(win, padding=(8, 0, 8, 4))
        action_bar.pack(fill="x")
        ttk.Label(
            action_bar, foreground="#555",
            text="Selecciona una o varias filas (Ctrl+clic para varias) y:",
        ).pack(side="left")
        ttk.Button(
            action_bar, text="Cerrar proceso(s) seleccionado(s)",
            command=lambda: self._close_selected_processes(tree),
        ).pack(side="left", padx=(8, 0))

        tree = ttk.Treeview(
            win, columns=("pid", "proceso", "local", "remoto", "origen", "ubicacion", "estado"), show="headings"
        )
        for col, label, width in [
            ("pid", "PID", 55), ("proceso", "Proceso", 130), ("local", "Direccion local", 140),
            ("remoto", "Direccion remota", 140), ("origen", "Origen", 170),
            ("ubicacion", "Ubicacion / ISP", 220), ("estado", "Estado", 80),
        ]:
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="w")
        tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        for conn in matches:
            ubicacion = conn.location if conn.isp in ("-", conn.location) else f"{conn.location} — {conn.isp}"
            tree.insert("", "end", values=(
                conn.pid or "-", conn.process, conn.local_addr, conn.remote_addr, conn.origin, ubicacion, conn.status,
            ))

        def on_double_click(_event):
            item = tree.focus()
            if not item:
                return
            pid_value = tree.item(item, "values")[0]
            pid = int(pid_value) if str(pid_value).isdigit() else None
            self._show_process_detail(pid)

        tree.bind("<Double-1>", on_double_click)

    def _close_selected_processes(self, tree: ttk.Treeview):
        selection = tree.selection()
        if not selection:
            messagebox.showinfo(APP_TITLE, "Selecciona primero una o mas filas de la lista.")
            return

        pids = sorted({
            int(tree.item(item, "values")[0])
            for item in selection
            if str(tree.item(item, "values")[0]).isdigit()
        })
        if not pids:
            messagebox.showinfo(APP_TITLE, "Ninguna de las filas seleccionadas tiene un PID valido para cerrar.")
            return

        proceed = messagebox.askyesno(
            APP_TITLE,
            f"¿Cerrar {len(pids)} proceso(s) (PID: {', '.join(map(str, pids))})?\n\n"
            "Esta accion es irreversible.",
        )
        if not proceed:
            return

        results = terminate_unknown(pids)
        resumen = "\n".join(
            f"PID {r.pid} ({r.name}): {'Cerrado' if r.success else 'No se pudo cerrar'} — {r.detail}"
            for r in results
        )
        messagebox.showinfo(APP_TITLE, f"Resultado:\n\n{resumen}")

        closed_pids = {r.pid for r in results if r.success}
        for item in selection:
            values = tree.item(item, "values")
            if str(values[0]).isdigit() and int(values[0]) in closed_pids:
                tree.delete(item)

    def _show_process_detail(self, pid):
        detail = inspect_process(pid)

        win = tk.Toplevel(self.root)
        win.title(f"Proceso: {detail.name} (PID {detail.pid})")
        win.geometry("560x380")
        win.resizable(False, False)

        rows = [
            ("Nombre", detail.name),
            ("PID", str(detail.pid)),
            ("Ruta del ejecutable", detail.exe),
            ("Usuario", detail.username),
            ("Iniciado", detail.started),
            ("Proceso padre", f"{detail.parent_name} (PID {detail.parent_pid})" if detail.parent_pid else detail.parent_name),
            ("Conexiones de red activas", str(detail.num_connections)),
            ("Linea de comandos", detail.cmdline),
        ]
        body = ttk.Frame(win, padding=12)
        body.pack(fill="both", expand=True)
        for i, (label, value) in enumerate(rows):
            ttk.Label(body, text=f"{label}:", font=("Segoe UI", 9, "bold")).grid(
                row=i, column=0, sticky="ne", padx=(0, 8), pady=3
            )
            ttk.Label(body, text=value, wraplength=380, justify="left").grid(
                row=i, column=1, sticky="nw", pady=3
            )

        if detail.error:
            ttk.Label(body, text=detail.error, foreground="#a33", wraplength=480, justify="left").grid(
                row=len(rows), column=0, columnspan=2, sticky="w", pady=(10, 0)
            )

        ttk.Label(
            win,
            text="Usa esta informacion (ruta, usuario, linea de comandos) para decidir si el "
                 "programa es confiable o si conviene restringir su acceso a la red.",
            wraplength=520, justify="left", foreground="#555", padding=(12, 0, 12, 12),
        ).pack(fill="x")

    # ---------- Worker (hilo en segundo plano) ----------
    def _poll_loop(self):
        while not self._stop_event.is_set():
            snapshot = self.monitor.take_snapshot()
            self._snapshot_queue.put(snapshot)
            time.sleep(self.requirements.refresh_interval_seconds)

    def _drain_queue(self):
        try:
            while True:
                snapshot = self._snapshot_queue.get_nowait()
                self._render_snapshot(snapshot)
        except queue.Empty:
            pass
        if self._running:
            self.root.after(200, self._drain_queue)

    def _render_snapshot(self, snapshot: Snapshot):
        self._latest_connections = snapshot.connections
        self.iface_tree.delete(*self.iface_tree.get_children())
        for iface in snapshot.interfaces:
            self.iface_tree.insert(
                "", "end", text=iface.name,
                values=(f"{iface.upload_mbps:.2f}", f"{iface.download_mbps:.2f}",
                        iface.bytes_sent_total, iface.bytes_recv_total),
            )

        self.category_tree.delete(*self.category_tree.get_children())
        for category, count in snapshot.category_counts.items():
            self.category_tree.insert("", "end", text=category, values=(count,))

        self.conn_tree.delete(*self.conn_tree.get_children())
        for conn in snapshot.connections:
            ubicacion = conn.location if conn.isp in ("-", conn.location) else f"{conn.location} — {conn.isp}"
            self.conn_tree.insert(
                "", "end",
                values=(conn.pid or "-", conn.process, conn.category,
                        conn.local_addr, conn.remote_addr, conn.origin, ubicacion, conn.status),
            )

        self.device_tree.delete(*self.device_tree.get_children())
        for device in snapshot.remote_devices:
            self.device_tree.insert(
                "", "end", text=device.ip,
                values=(device.hostname, device.connections, device.processes,
                        device.first_seen, device.last_seen),
            )

        self.egress_tree.delete(*self.egress_tree.get_children())
        for event in snapshot.egress_events:
            ubicacion = event.location if event.isp in ("-", event.location) else f"{event.location} — {event.isp}"
            destino = f"{event.remote_ip}:{event.remote_port}"
            self.egress_tree.insert("", "end", values=(
                event.pid or "-", event.first_seen, event.last_seen, f"{event.duration_seconds:.0f}s",
                event.process, event.category, destino, event.protocol, event.origin,
                ubicacion, f"{event.estimated_mb:.2f} MB",
                "En curso" if event.active else "Finalizada",
            ))

        self.attack_tree.delete(*self.attack_tree.get_children())
        for event in snapshot.attack_events:
            ubicacion = event.location if event.isp in ("-", event.location) else f"{event.location} — {event.isp}"
            self.attack_tree.insert("", "end", values=(
                event.local_pid or "-", event.kind, event.source_ip, ubicacion,
                event.local_process, event.detail, event.first_seen, event.last_seen, event.hit_count,
            ))
            popup_key = (event.source_ip, event.kind)
            if popup_key not in self._attack_popup_shown:
                self._attack_popup_shown.add(popup_key)
                self._show_attack_popup(event)

        self.alert_text.config(state="normal")
        self.alert_text.delete("1.0", "end")
        self.alert_text.insert("end", "\n".join(snapshot.alerts) if snapshot.alerts else "Sin alertas.")
        self.alert_text.config(state="disabled")

        if snapshot.alerts:
            self._start_alert_blink()
        else:
            self._stop_alert_blink()

    def _on_close(self):
        self.stop_monitoring()
        self.root.destroy()


def main():
    root = tk.Tk()
    MonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
