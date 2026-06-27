"""
Implementacion de los pasos definidos por el Agente 2, usando psutil.
Esta capa no tiene interfaz: solo produce datos (Snapshot). El Agente 3
(Generador de Codigo / app.py) la usa para alimentar la GUI.
"""

import csv
import ipaddress
import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import psutil

import geo_lookup
import hostname_lookup
from flow_architect import MonitoringWorkflow
from port_protocols import guess_protocol
from process_classifier import classify_process

SENSITIVE_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900}


@dataclass
class InterfaceRate:
    name: str
    upload_mbps: float
    download_mbps: float
    bytes_sent_total: int
    bytes_recv_total: int


@dataclass
class ConnectionInfo:
    pid: Optional[int]
    process: str
    category: str
    local_addr: str
    remote_addr: str
    origin: str
    location: str
    isp: str
    status: str


@dataclass
class RemoteDevice:
    ip: str
    hostname: str
    connections: int
    processes: str
    first_seen: str
    last_seen: str


@dataclass
class EgressEvent:
    pid: Optional[int]
    process: str
    category: str
    remote_ip: str
    remote_port: int
    origin: str
    location: str
    isp: str
    protocol: str
    first_seen: str
    last_seen: str
    duration_seconds: float
    estimated_mb: float
    active: bool


@dataclass
class AttackEvent:
    kind: str
    source_ip: str
    detail: str
    location: str
    isp: str
    local_pid: Optional[int]
    local_process: str
    first_seen: str
    last_seen: str
    hit_count: int


@dataclass
class Snapshot:
    timestamp: float
    interfaces: List[InterfaceRate]
    connections: List[ConnectionInfo]
    category_counts: Dict[str, int]
    remote_devices: List[RemoteDevice]
    egress_events: List[EgressEvent]
    attack_events: List[AttackEvent]
    alerts: List[str]


class TrafficMonitor:
    def __init__(self, workflow: MonitoringWorkflow):
        self.workflow = workflow
        self.requirements = workflow.requirements
        self._step_names = {s.name for s in workflow.steps}
        self._last_counters: Dict[str, "psutil._common.snetio"] = {}
        self._last_time: Optional[float] = None
        self._own_ips = self._collect_own_ips()
        self._known_lan_devices: Dict[str, dict] = {}
        self._new_devices_this_pass: List[str] = []
        self._last_sent_delta_bytes = 0
        self._egress_sessions: Dict[tuple, dict] = {}
        self._egress_finalized: List[EgressEvent] = []
        self._seen_conn_keys_for_attack: Dict[tuple, float] = {}
        self._inbound_attempts: Dict[str, List[tuple]] = {}
        self._attack_active: Dict[tuple, dict] = {}

    @staticmethod
    def _collect_own_ips() -> set:
        ips = {"127.0.0.1", "::1"}
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family.name in ("AF_INET", "AF_INET6"):
                    ips.add(a.address.split("%")[0])
        return ips

    def _collect_io_counters(self):
        return psutil.net_io_counters(pernic=True)

    def _compute_rates(self, counters) -> List[InterfaceRate]:
        now = time.time()
        elapsed = (now - self._last_time) if self._last_time else None
        rates = []
        total_sent_delta = 0
        for name, stat in counters.items():
            prev = self._last_counters.get(name)
            upload_mbps = download_mbps = 0.0
            if prev is not None and elapsed and elapsed > 0:
                sent_delta = max(stat.bytes_sent - prev.bytes_sent, 0)
                recv_delta = max(stat.bytes_recv - prev.bytes_recv, 0)
                upload_mbps = (sent_delta * 8 / 1_000_000) / elapsed
                download_mbps = (recv_delta * 8 / 1_000_000) / elapsed
                total_sent_delta += sent_delta
            rates.append(InterfaceRate(
                name=name,
                upload_mbps=round(upload_mbps, 3),
                download_mbps=round(download_mbps, 3),
                bytes_sent_total=stat.bytes_sent,
                bytes_recv_total=stat.bytes_recv,
            ))
        self._last_counters = counters
        self._last_time = now
        self._last_sent_delta_bytes = total_sent_delta
        return rates

    def _classify_origin(self, remote_ip: str) -> str:
        if not remote_ip:
            return "-"
        try:
            addr = ipaddress.ip_address(remote_ip)
        except ValueError:
            return "Desconocido"
        if addr.is_loopback or remote_ip in self._own_ips:
            return "Este equipo"
        if addr.is_private:
            return "Red local (otro dispositivo)"
        return "Internet"

    @staticmethod
    def _lookup_geo(remote_ip: str, origin: str):
        if origin != "Internet" or not remote_ip:
            return "-", "-"
        geo_lookup.request_lookup(remote_ip)
        cached = geo_lookup.get_cached(remote_ip)
        if cached is None or cached == geo_lookup.PENDING:
            return "Buscando...", "Buscando..."
        if cached == geo_lookup.ERROR:
            return "No disponible", "No disponible"
        return cached.label(), (cached.isp or "-")

    def _collect_connections(self) -> List[ConnectionInfo]:
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = []
        listening_ports = {c.laddr.port for c in conns if c.status == "LISTEN" and c.laddr}
        result = []
        lan_hits: Dict[str, List[str]] = {}
        for c in conns[: self.requirements.max_connections_listed]:
            proc_name = "?"
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "?"
            category = classify_process(proc_name)
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            raddr_ip = c.raddr.ip if c.raddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            origin = self._classify_origin(raddr_ip)
            if origin == "Red local (otro dispositivo)":
                lan_hits.setdefault(raddr_ip, []).append(proc_name)
            location, isp = self._lookup_geo(raddr_ip, origin)
            result.append(ConnectionInfo(
                pid=c.pid, process=proc_name, category=category,
                local_addr=laddr, remote_addr=raddr, origin=origin,
                location=location, isp=isp, status=c.status,
            ))
            local_port = self._extract_port(laddr)
            if (
                "detect_attacks" in self._step_names
                and origin in ("Internet", "Red local (otro dispositivo)")
                and raddr_ip
                and local_port in listening_ports
            ):
                remote_port = c.raddr.port if c.raddr else 0
                key = (c.pid, raddr_ip, remote_port, local_port)
                now = time.time()
                if key not in self._seen_conn_keys_for_attack:
                    self._seen_conn_keys_for_attack[key] = now
                    self._observe_attack_signal(raddr_ip, local_port, proc_name, c.pid, now)
        if "detect_remote_systems" in self._step_names:
            self._update_lan_devices(lan_hits, time.time())
        if "detect_attacks" in self._step_names:
            cutoff = time.time() - (self.requirements.attack_window_seconds * 4)
            self._seen_conn_keys_for_attack = {
                k: t for k, t in self._seen_conn_keys_for_attack.items() if t >= cutoff
            }
        return result

    @staticmethod
    def _extract_port(addr: str) -> int:
        _, _, port_str = addr.rpartition(":")
        return int(port_str) if port_str.isdigit() else 0

    def _update_lan_devices(self, lan_hits: Dict[str, List[str]], now: float):
        self._new_devices_this_pass = []
        for ip, procs in lan_hits.items():
            entry = self._known_lan_devices.get(ip)
            if entry is None:
                self._known_lan_devices[ip] = {
                    "first_seen": now, "last_seen": now,
                    "connections": len(procs), "processes": set(procs),
                }
                self._new_devices_this_pass.append(ip)
            else:
                entry["last_seen"] = now
                entry["connections"] = len(procs)
                entry["processes"].update(procs)

    def _remote_devices_snapshot(self) -> List[RemoteDevice]:
        devices = []
        for ip, info in self._known_lan_devices.items():
            hostname_lookup.request_lookup(ip)
            hostname = hostname_lookup.get_cached(ip)
            if hostname is None or hostname == hostname_lookup.PENDING:
                hostname = "Buscando..."
            devices.append(RemoteDevice(
                ip=ip,
                hostname=hostname,
                connections=info["connections"],
                processes=", ".join(sorted(info["processes"])),
                first_seen=time.strftime("%H:%M:%S", time.localtime(info["first_seen"])),
                last_seen=time.strftime("%H:%M:%S", time.localtime(info["last_seen"])),
            ))
        return sorted(devices, key=lambda d: d.last_seen, reverse=True)

    def _update_egress_sessions(self, connections: List[ConnectionInfo]) -> List[EgressEvent]:
        now = time.time()
        current_keys = set()

        for c in connections:
            if c.origin not in ("Internet", "Red local (otro dispositivo)"):
                continue
            if c.status != "ESTABLISHED" or not c.remote_addr or c.remote_addr == "-":
                continue
            ip, _, port_str = c.remote_addr.rpartition(":")
            port = int(port_str) if port_str.isdigit() else 0
            key = (c.pid, ip, port)
            current_keys.add(key)
            session = self._egress_sessions.get(key)
            if session is None:
                self._egress_sessions[key] = {
                    "first_seen": now, "last_seen": now, "process": c.process, "pid": c.pid,
                    "category": c.category, "origin": c.origin, "location": c.location,
                    "isp": c.isp, "remote_ip": ip, "remote_port": port, "estimated_bytes": 0.0,
                }
            else:
                session["last_seen"] = now

        if current_keys and self._last_sent_delta_bytes:
            share = self._last_sent_delta_bytes / len(current_keys)
            for key in current_keys:
                self._egress_sessions[key]["estimated_bytes"] += share

        ended_keys = [k for k in self._egress_sessions if k not in current_keys]
        for key in ended_keys:
            session = self._egress_sessions.pop(key)
            event = self._build_egress_event(session, active=False)
            self._egress_finalized.append(event)
            if self.requirements.track_egress:
                self._persist_egress_event(event)
        self._egress_finalized = self._egress_finalized[-200:]

        active_events = [self._build_egress_event(s, active=True) for s in self._egress_sessions.values()]
        combined = active_events + self._egress_finalized[-100:]
        return sorted(combined, key=lambda e: e.first_seen, reverse=True)

    @staticmethod
    def _build_egress_event(session: dict, active: bool) -> EgressEvent:
        duration = max(session["last_seen"] - session["first_seen"], 0.0)
        return EgressEvent(
            pid=session["pid"], process=session["process"], category=session["category"],
            remote_ip=session["remote_ip"], remote_port=session["remote_port"], origin=session["origin"],
            location=session["location"], isp=session["isp"], protocol=guess_protocol(session["remote_port"]),
            first_seen=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(session["first_seen"])),
            last_seen=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(session["last_seen"])),
            duration_seconds=round(duration, 1),
            estimated_mb=round(session["estimated_bytes"] / (1024 * 1024), 3),
            active=active,
        )

    def _persist_egress_event(self, event: EgressEvent):
        path = self.requirements.egress_log_path
        is_new = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if is_new:
                writer.writerow([
                    "inicio", "fin", "duracion_seg", "pid", "proceso", "categoria",
                    "ip_remota", "puerto", "protocolo", "origen", "ubicacion", "isp", "mb_estimados",
                ])
            writer.writerow([
                event.first_seen, event.last_seen, event.duration_seconds, event.pid, event.process,
                event.category, event.remote_ip, event.remote_port, event.protocol, event.origin,
                event.location, event.isp, event.estimated_mb,
            ])

    def _observe_attack_signal(self, remote_ip: str, local_port: int, proc_name: str, pid, now: float):
        req = self.requirements
        history = self._inbound_attempts.setdefault(remote_ip, [])
        history.append((now, local_port))
        cutoff = now - req.attack_window_seconds
        history[:] = [(t, p) for (t, p) in history if t >= cutoff]

        distinct_ports = sorted({p for _, p in history})
        if len(distinct_ports) >= req.port_scan_threshold:
            self._raise_attack_event(
                remote_ip, "Escaneo de puertos", now, proc_name, pid,
                f"Conexiones a {len(distinct_ports)} puertos distintos en {req.attack_window_seconds}s: "
                f"{distinct_ports}",
            )

        port_counts: Dict[int, int] = {}
        for _, p in history:
            if p in SENSITIVE_PORTS:
                port_counts[p] = port_counts.get(p, 0) + 1
        for port, count in port_counts.items():
            if count >= req.brute_force_threshold:
                self._raise_attack_event(
                    remote_ip, "Posible fuerza bruta", now, proc_name, pid,
                    f"{count} intentos al puerto {port} ({guess_protocol(port)}) en {req.attack_window_seconds}s",
                )

    def _raise_attack_event(self, remote_ip: str, kind: str, now: float, proc_name: str, pid, detail: str):
        key = (remote_ip, kind)
        is_new = key not in self._attack_active
        entry = self._attack_active.setdefault(key, {"first_seen": now, "hit_count": 0})
        entry["last_seen"] = now
        entry["detail"] = detail
        entry["local_process"] = proc_name
        entry["local_pid"] = pid
        entry["hit_count"] += 1
        if is_new:
            self._persist_attack_event(remote_ip, kind, detail, proc_name, pid, now)

    def _persist_attack_event(self, remote_ip: str, kind: str, detail: str, proc_name: str, pid, now: float):
        origin = self._classify_origin(remote_ip)
        location, isp = self._lookup_geo(remote_ip, origin)
        path = self.requirements.attack_log_path
        is_new = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if is_new:
                writer.writerow([
                    "timestamp", "tipo", "ip_origen", "origen", "ubicacion", "isp",
                    "proceso_local", "pid_local", "detalle",
                ])
            writer.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                kind, remote_ip, origin, location, isp, proc_name, pid or "-", detail,
            ])

    def _attack_events_snapshot(self, now: float) -> List[AttackEvent]:
        req = self.requirements
        expired = [
            k for k, v in self._attack_active.items()
            if now - v["last_seen"] > req.attack_window_seconds * 2
        ]
        for k in expired:
            del self._attack_active[k]

        events = []
        for (ip, kind), info in self._attack_active.items():
            origin = self._classify_origin(ip)
            location, isp = self._lookup_geo(ip, origin)
            if origin == "Red local (otro dispositivo)":
                hostname_lookup.request_lookup(ip)
                hostname = hostname_lookup.get_cached(ip)
                location = "Tu red local" if not hostname or hostname == hostname_lookup.PENDING else f"Tu red local — {hostname}"
                isp = "-"
            events.append(AttackEvent(
                kind=kind, source_ip=ip, detail=info["detail"], location=location, isp=isp,
                local_pid=info.get("local_pid"), local_process=info.get("local_process", "?"),
                first_seen=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info["first_seen"])),
                last_seen=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info["last_seen"])),
                hit_count=info["hit_count"],
            ))
        return sorted(events, key=lambda e: e.last_seen, reverse=True)

    def _category_counts(self, connections: List[ConnectionInfo]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for c in connections:
            counts[c.category] = counts.get(c.category, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))

    def _evaluate_alerts(self, interfaces, connections) -> List[str]:
        req = self.requirements
        alerts = []
        for iface in interfaces:
            total = iface.upload_mbps + iface.download_mbps
            if total >= req.bandwidth_alert_mbps:
                alerts.append(
                    f"Trafico alto en {iface.name}: {total:.1f} Mbps "
                    f"(umbral {req.bandwidth_alert_mbps:.0f} Mbps)"
                )
        if len(connections) >= req.connection_count_alert:
            alerts.append(
                f"Numero elevado de conexiones activas: {len(connections)} "
                f"(umbral {req.connection_count_alert})"
            )
        if "detect_remote_systems" in self._step_names:
            for ip in self._new_devices_this_pass:
                alerts.append(f"Nuevo dispositivo detectado en tu red local: {ip} (no es este equipo)")
        return alerts

    def _persist_log(self, snapshot: Snapshot):
        path = self.requirements.log_path
        is_new = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if is_new:
                writer.writerow(["timestamp", "interface", "upload_mbps", "download_mbps", "alertas"])
            for iface in snapshot.interfaces:
                writer.writerow([
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(snapshot.timestamp)),
                    iface.name, iface.upload_mbps, iface.download_mbps,
                    "; ".join(snapshot.alerts),
                ])

    def take_snapshot(self) -> Snapshot:
        interfaces: List[InterfaceRate] = []
        connections: List[ConnectionInfo] = []
        if "collect_io_counters" in self._step_names:
            counters = self._collect_io_counters()
            if "compute_rates" in self._step_names:
                interfaces = self._compute_rates(counters)
        if "collect_connections" in self._step_names:
            connections = self._collect_connections()
        category_counts = self._category_counts(connections) if "classify_processes" in self._step_names else {}
        remote_devices = self._remote_devices_snapshot() if "detect_remote_systems" in self._step_names else []
        egress_events = self._update_egress_sessions(connections) if "track_egress" in self._step_names else []
        now = time.time()
        attack_events = self._attack_events_snapshot(now) if "detect_attacks" in self._step_names else []
        alerts = self._evaluate_alerts(interfaces, connections) if "evaluate_alerts" in self._step_names else []
        for event in attack_events:
            alerts.append(
                f"{event.kind} desde {event.source_ip} ({event.location}) hacia "
                f"{event.local_process} (PID {event.local_pid}): {event.detail}"
            )
        snapshot = Snapshot(
            timestamp=now, interfaces=interfaces, connections=connections,
            category_counts=category_counts, remote_devices=remote_devices,
            egress_events=egress_events, attack_events=attack_events, alerts=alerts,
        )
        if "persist_log" in self._step_names and self.requirements.log_to_file:
            self._persist_log(snapshot)
        return snapshot
