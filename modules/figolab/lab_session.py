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

from modules.figolab.ap import build_dnsmasq_conf, build_hostapd_conf, count_dhcp_leases
from modules.figolab.awareness.metrics import MetricsStore
from modules.figolab.awareness.portal import AwarenessPortal
from modules.figolab.awareness.session import SessionStore
from modules.figolab.interface import InterfaceSnapshot, restore_interface, set_nm_managed, snapshot_interface
from modules.figolab.models import LAB_BINS, LabConfig
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
    leases_path: Optional[Path] = None
    started_at: float = 0.0
    ap_active: bool = False
    portal_active: bool = False
    _cleaned: bool = False
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

    # Unmanage from NetworkManager to avoid fights with hostapd.
    set_nm_managed(iface, False)

    code, out = _run([ip, "link", "set", iface, "down"])
    if code != 0:
        raise LabError(f"Failed to bring {iface} down.\n{out}")

    # Ensure station/managed before AP tooling claims it.
    _run([iw, "dev", iface, "set", "type", "managed"])
    _run([ip, "addr", "flush", "dev", iface])

    code, out = _run([ip, "link", "set", iface, "up"])
    if code != 0:
        raise LabError(f"Failed to bring {iface} up.\n{out}")

    code, out = _run([ip, "addr", "add", f"{config.gateway_ip}/24", "dev", iface])
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

        session.tracker.start("hostapd", [hostapd, str(session.hostapd_conf)])
        time.sleep(0.8)
        if not session.tracker.alive("hostapd"):
            raise LabError(
                "Failed to start the lab AP.\n"
                "Possible causes:\n"
                "- Adapter does not support AP mode.\n"
                "- hostapd configuration is invalid.\n"
                "- Another process is using the interface."
            )
        session.ap_active = True

        session.tracker.start(
            "dnsmasq",
            [dnsmasq, "-C", str(session.dnsmasq_conf), "-d"],
        )
        time.sleep(0.4)
        if not session.tracker.alive("dnsmasq"):
            raise LabError(
                "Failed to start DHCP/DNS (dnsmasq).\n"
                "Possible causes:\n"
                "- Port 53 already in use\n"
                "- Invalid dnsmasq configuration\n"
                "- Interface not ready"
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
