"""Lab session orchestration, startup, dashboard helpers, and cleanup."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from modules.figolab.ap import (
    build_dnsmasq_conf,
    build_hostapd_conf,
    count_dhcp_leases,
    parse_dhcp_leases,
)
from modules.figolab.awareness.metrics import MetricsStore, assert_no_sensitive_payload, utc_now_iso
from modules.figolab.awareness.portal import AwarenessPortal
from modules.figolab.awareness.session import SessionStore
from modules.figolab.interface import (
    InterfaceSnapshot,
    restore_interface,
    rfkill_unblock,
    set_nm_managed,
    snapshot_interface,
    stop_interfering_processes,
)
from modules.figolab.models import LAB_BINS, LabConfig, channel_band
from modules.figolab.processes import ProcessTracker


class LabError(RuntimeError):
    """Raised when the lab cannot start or continue safely."""


def detect_lab_dependencies() -> list[str]:
    return [name for name in LAB_BINS if not shutil.which(name)]


@dataclass
class LabSession:
    config: LabConfig
    tracker: ProcessTracker = field(default_factory=ProcessTracker)
    metrics: MetricsStore = field(default_factory=MetricsStore)
    sessions: Optional[SessionStore] = None
    portal: Optional[AwarenessPortal] = None
    snapshot: Optional[InterfaceSnapshot] = None
    temp_dir: Optional[Path] = None
    hostapd_conf: Optional[Path] = None
    dnsmasq_conf: Optional[Path] = None
    hostapd_log: Optional[Path] = None
    dnsmasq_log: Optional[Path] = None
    leases_path: Optional[Path] = None
    started_at: float = 0.0
    ap_active: bool = False
    portal_active: bool = False
    _cleaned: bool = False
    _portal_restarts: int = 0
    _log_handles: list = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def runtime_sec(self) -> int:
        if not self.started_at:
            return 0
        return max(0, int(time.time() - self.started_at))

    def refresh_client_count(self) -> int:
        path = self.leases_path
        count = count_dhcp_leases(path) if path else 0
        self.metrics.set_connected_devices(count)
        return count

    def recent_clients(self, limit: int = 6) -> list[dict[str, str]]:
        if not self.leases_path:
            return []
        clients = parse_dhcp_leases(self.leases_path)
        return clients[-max(1, int(limit)):]

    def ap_ok(self) -> bool:
        return self.ap_active and self.tracker.alive("hostapd")

    def dnsmasq_ok(self) -> bool:
        return self.tracker.alive("dnsmasq")

    def portal_ok(self) -> bool:
        return bool(self.portal is not None and self.portal.alive())

    def ensure_services(self) -> None:
        """
        Best-effort self-healing for the live dashboard.

        Currently restarts the awareness portal if its HTTP server died, up to a
        small retry budget. AP/DHCP failures are surfaced to the operator rather
        than silently restarted (they usually indicate a hardware/driver issue).
        """
        if not self.portal_active or self.portal is None:
            return
        if self.portal.alive():
            return
        if self._portal_restarts >= 3:
            return
        self._portal_restarts += 1
        try:
            self.portal.stop()
        except Exception:
            pass
        try:
            self.portal.start(bind_host=self.config.gateway_ip)
        except OSError:
            try:
                self.portal.start(bind_host="0.0.0.0")
            except OSError:
                self.portal_active = False
                self.metrics.add_event("service", "Portal failed to restart")
                return
        self.metrics.add_event(
            "service", f"Portal auto-restarted (attempt {self._portal_restarts})"
        )


_ACTIVE: Optional[LabSession] = None
_ACTIVE_LOCK = threading.RLock()


def get_active_session() -> Optional[LabSession]:
    with _ACTIVE_LOCK:
        return _ACTIVE


def _set_active(session: Optional[LabSession]) -> None:
    global _ACTIVE
    with _ACTIVE_LOCK:
        _ACTIVE = session


def prepare_interface(config: LabConfig, snapshot: InterfaceSnapshot) -> None:
    iface = config.interface
    ip = shutil.which("ip")
    iw = shutil.which("iw")
    if not ip or not iw:
        raise LabError("Missing ip or iw — cannot prepare the wireless interface.")

    # Fail fast if the adapter cannot do AP mode — clearer than a cryptic
    # hostapd crash later. Only block when support is explicitly False.
    try:
        from modules.preflight import probe_adapter_capabilities

        caps = probe_adapter_capabilities(iface)
        if caps.supports_ap is False:
            raise LabError(
                f"Adapter {iface} does not support AP (master) mode.\n"
                "Possible fixes:\n"
                "- Use a wireless adapter that supports AP mode.\n"
                "- Check `iw list` → 'Supported interface modes' for 'AP'.\n"
                "- Some drivers need a different chipset for hostapd."
            )
    except LabError:
        raise
    except Exception:
        # Capability probing is best-effort; never block on probe errors.
        pass

    # Clear soft rfkill blocks and release the adapter from anything holding it.
    rfkill_unblock()
    set_nm_managed(iface, False)
    killed = stop_interfering_processes(iface)
    if killed:
        time.sleep(0.3)

    code, out = _run([ip, "link", "set", iface, "down"])
    if code != 0:
        raise LabError(f"Failed to bring {iface} down.\n{out}")

    # Ensure station/managed before AP tooling claims it.
    _run([iw, "dev", iface, "set", "type", "managed"])
    _run([ip, "addr", "flush", "dev", iface])

    code, out = _run([ip, "link", "set", iface, "up"])
    if code != 0:
        raise LabError(f"Failed to bring {iface} up.\n{out}")

    code, out = _run(
        [ip, "addr", "add", f"{config.gateway_ip}/{int(config.subnet_prefix)}", "dev", iface]
    )
    if code != 0 and "File exists" not in out:
        raise LabError(
            "Failed to assign lab gateway address.\n"
            f"{out}\n"
            "Possible causes:\n"
            "- Interface already has conflicting addresses\n"
            "- Another process is using the interface"
        )

    config.ap_interface = iface


def start_lab_session(config: LabConfig, *, enable_portal: bool) -> LabSession:
    missing = detect_lab_dependencies()
    if missing:
        raise LabError("Required dependency not found: " + ", ".join(missing))

    ok, err = config.validate()
    if not ok:
        raise LabError(err)

    if get_active_session() is not None:
        raise LabError("A lab session is already active. Stop it before starting another.")

    session = LabSession(config=config)
    session.sessions = SessionStore(ttl_sec=config.portal.session_ttl_sec)
    session.temp_dir = Path(tempfile.mkdtemp(prefix="figo-lab-"))
    session.hostapd_conf = session.temp_dir / "hostapd.conf"
    session.dnsmasq_conf = session.temp_dir / "dnsmasq.conf"
    session.hostapd_log = session.temp_dir / "hostapd.log"
    session.dnsmasq_log = session.temp_dir / "dnsmasq.log"
    session.leases_path = session.temp_dir / "dnsmasq.leases"
    session.leases_path.write_text("", encoding="utf-8")

    try:
        session.snapshot = snapshot_interface(config.interface)
        prepare_interface(config, session.snapshot)

        build_hostapd_conf(config, session.hostapd_conf)
        build_dnsmasq_conf(config, session.dnsmasq_conf, leases_path=session.leases_path)

        hostapd = shutil.which("hostapd")
        dnsmasq = shutil.which("dnsmasq")
        assert hostapd and dnsmasq

        # hostapd: capture output so failures produce actionable messages, and
        # confirm the AP actually enabled instead of just "process is alive".
        hostapd_out = _open_log(session, session.hostapd_log)
        session.tracker.start(
            "hostapd",
            [hostapd, str(session.hostapd_conf)],
            stdout=hostapd_out,
            stderr=subprocess.STDOUT,
        )
        if not _wait_for_hostapd(session, timeout=6.0):
            tail = _read_tail(session.hostapd_log)
            raise LabError(
                "Failed to start the lab AP.\n"
                "Possible causes:\n"
                "- Adapter does not support AP mode.\n"
                "- hostapd configuration is invalid or channel unsupported.\n"
                "- Another process is using the interface.\n"
                + (f"\nhostapd said:\n{tail}" if tail else "")
            )
        session.ap_active = True

        dnsmasq_out = _open_log(session, session.dnsmasq_log)
        session.tracker.start(
            "dnsmasq",
            [dnsmasq, "-C", str(session.dnsmasq_conf), "-d"],
            stdout=dnsmasq_out,
            stderr=subprocess.STDOUT,
        )
        if not _wait_alive(session, "dnsmasq", timeout=2.0):
            tail = _read_tail(session.dnsmasq_log)
            raise LabError(
                "Failed to start DHCP/DNS (dnsmasq).\n"
                "Possible causes:\n"
                "- Port 53 already in use (e.g. systemd-resolved)\n"
                "- Invalid dnsmasq configuration\n"
                "- Interface not ready\n"
                + (f"\ndnsmasq said:\n{tail}" if tail else "")
            )

        if enable_portal and config.portal_enabled:
            session.portal = AwarenessPortal(config, session.metrics, session.sessions)
            try:
                session.portal.start(bind_host=config.gateway_ip)
            except OSError:
                # Fall back to all interfaces if gateway bind fails in dry environments.
                session.portal.start(bind_host="0.0.0.0")
            session.portal_active = True

        session.started_at = time.time()
        _set_active(session)
        return session
    except Exception:
        cleanup_lab_session(session)
        raise


def _open_log(session: LabSession, path: Path):
    handle = open(path, "wb", buffering=0)
    session._log_handles.append(handle)
    return handle


def _read_tail(path: Optional[Path], max_lines: int = 15) -> str:
    if not path or not path.exists():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    tail = [ln for ln in lines if ln.strip()][-max_lines:]
    return "\n".join(tail)


def _wait_alive(session: LabSession, name: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    # Give the process a brief moment to fail fast.
    time.sleep(min(0.4, timeout))
    while time.time() < deadline:
        if not session.tracker.alive(name):
            return False
        time.sleep(0.1)
    return session.tracker.alive(name)


def _wait_for_hostapd(session: LabSession, timeout: float) -> bool:
    """
    Return True once hostapd reports the AP is enabled, or it is still alive at
    timeout (some drivers do not print AP-ENABLED). Return False if it exits or
    logs a fatal error.
    """
    deadline = time.time() + timeout
    fatal_markers = ("AP-DISABLED", "Could not configure driver mode", "nl80211: Could not")
    while time.time() < deadline:
        if not session.tracker.alive("hostapd"):
            return False
        log = _read_tail(session.hostapd_log, max_lines=40)
        if "AP-ENABLED" in log:
            return True
        if any(marker in log for marker in fatal_markers):
            return False
        time.sleep(0.15)
    return session.tracker.alive("hostapd")


def cleanup_lab_session(session: Optional[LabSession] = None) -> None:
    """
    Central cleanup. Safe and idempotent — calling twice must not raise.
    """
    session = session or get_active_session()
    if session is None:
        return

    with session._lock:
        if session._cleaned:
            if get_active_session() is session:
                _set_active(None)
            return
        session._cleaned = True

        # 1. Stop awareness portal
        if session.portal is not None:
            try:
                session.portal.stop()
            except Exception:
                pass
            session.portal_active = False

        # 2–4. Stop DHCP/DNS, AP, and tracked children
        try:
            session.tracker.terminate_all()
        except Exception:
            pass
        session.ap_active = False

        # Close captured hostapd/dnsmasq log file handles.
        for handle in session._log_handles:
            try:
                handle.close()
            except Exception:
                pass
        session._log_handles.clear()

        # 5–6. Remove temporary configuration / session data
        if session.sessions is not None:
            try:
                session.sessions.clear()
            except Exception:
                pass
        try:
            session.metrics.clear()
        except Exception:
            pass
        if session.temp_dir is not None:
            _rm_tree(session.temp_dir)

        # 7–9. Restore wireless interface / NM state
        if session.snapshot is not None:
            try:
                restore_interface(session.snapshot)
            except Exception:
                pass

        if get_active_session() is session:
            _set_active(None)


def _rm_tree(path: Path) -> None:
    if not path.exists():
        return
    for child in sorted(path.rglob("*"), reverse=True):
        try:
            if child.is_file() or child.is_symlink():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
        except OSError:
            pass
    try:
        path.rmdir()
    except OSError:
        pass


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return proc.returncode, out
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 1, f"Timed out: {' '.join(cmd)}"


def dry_run_lab_configs(config: LabConfig) -> tuple[str, str, str]:
    """
    Build hostapd/dnsmasq configs in a temp dir, return (hostapd_text, dnsmasq_text, notes).
    Does not start any processes. Temp files are removed.
    """
    ok, err = config.validate()
    if not ok:
        raise LabError(err)
    missing = detect_lab_dependencies()
    notes = []
    if missing:
        notes.append("Missing tools (dry-run still shows config): " + ", ".join(missing))
    temp_dir = Path(tempfile.mkdtemp(prefix="figo-lab-dry-"))
    try:
        hostapd_path = temp_dir / "hostapd.conf"
        dnsmasq_path = temp_dir / "dnsmasq.conf"
        leases_path = temp_dir / "dnsmasq.leases"
        leases_path.write_text("", encoding="utf-8")
        build_hostapd_conf(config, hostapd_path)
        build_dnsmasq_conf(config, dnsmasq_path, leases_path=leases_path)
        hostapd_text = hostapd_path.read_text(encoding="utf-8")
        dnsmasq_text = dnsmasq_path.read_text(encoding="utf-8")
        security = "WPA2 (secured)" if config.is_secured() else "open"
        notes.append(
            f"SSID={config.effective_ssid()} channel={config.channel} "
            f"security={security} "
            f"gateway={config.gateway_ip}/{config.subnet_prefix} "
            f"portal=:80 (captive) + :{config.portal_port}"
        )
        return hostapd_text, dnsmasq_text, "\n".join(notes)
    finally:
        _rm_tree(temp_dir)


def build_session_report(session: LabSession) -> tuple[dict, str]:
    """
    Build a shareable session report (dict + human-readable text) for the
    manual debrief. Contains only non-sensitive assessment data — never any
    submitted value, and never the AP passphrase. Call this BEFORE cleanup,
    because cleanup clears live metrics and lease files.
    """
    config = session.config
    snap = session.metrics.snapshot()
    clients = session.recent_clients(limit=100)
    report = {
        "generated_at": utc_now_iso(),
        "runtime_sec": session.runtime_sec(),
        "lab": {
            "ssid": config.effective_ssid(),
            "channel": str(config.channel),
            "band": channel_band(config.channel),
            "ap_security": "wpa2" if config.is_secured() else "open",
            "gateway": f"{config.gateway_ip}/{config.subnet_prefix}",
            "dhcp_range": f"{config.dhcp_range_start}-{config.dhcp_range_end}",
            "portal_ports": [80, int(config.portal_port)],
        },
        "metrics": {
            "connected_devices": snap["connected_devices"],
            "portal_visits": snap["portal_visits"],
            "login_submissions": snap["login_submissions"],
            "passwords_entered": snap["passwords_entered"],
            "interactions": snap["interactions"],
            "completed": snap["completed"],
        },
        "clients": clients,
        "events": snap.get("events", []),
    }
    # Defence in depth: make sure nothing sensitive slipped into the payload.
    assert_no_sensitive_payload(report["lab"])
    assert_no_sensitive_payload(report["metrics"])

    m = report["metrics"]
    lines = [
        "FIGO SECURITY AWARENESS — SESSION REPORT",
        "=" * 42,
        f"Generated : {report['generated_at']}",
        f"Runtime   : {report['runtime_sec']}s",
        "",
        f"SSID      : {report['lab']['ssid']}",
        f"Channel   : {report['lab']['channel']} ({report['lab']['band']})",
        f"AP secure : {report['lab']['ap_security']}",
        f"Gateway   : {report['lab']['gateway']}",
        "",
        "RESULTS",
        "-" * 42,
        f"Connected devices  : {m['connected_devices']}",
        f"Portal visits      : {m['portal_visits']}",
        f"Sign-in submissions: {m['login_submissions']}",
        f"Passwords entered  : {m['passwords_entered']}   (values never stored)",
        f"Interactions       : {m['interactions']}",
        f"Completed          : {m['completed']}",
        "",
        "CONNECTED CLIENTS",
        "-" * 42,
    ]
    if clients:
        for c in clients:
            host = c.get("hostname") or "-"
            lines.append(f"  {c.get('mac', '?'):<18} {c.get('ip', '?'):<15} {host}")
    else:
        lines.append("  (none recorded)")
    lines += ["", "EVENT LOG", "-" * 42]
    for ev in report["events"]:
        lines.append(f"  {ev.get('ts', '')}  {ev.get('kind', '')}: {ev.get('message', '')}")
    text = "\n".join(lines) + "\n"
    return report, text


def save_session_report(report: dict, text: str, *, directory: Optional[Path] = None) -> Path:
    """Write the report as timestamped .json + .txt; returns the .txt path."""
    import json

    directory = directory or (Path.home() / "figo-reports")
    directory.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = directory / f"awareness-{stamp}"
    json_path = base.with_suffix(".json")
    txt_path = base.with_suffix(".txt")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    txt_path.write_text(text, encoding="utf-8")
    return txt_path
