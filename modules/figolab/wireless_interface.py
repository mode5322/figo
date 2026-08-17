"""Wireless interface snapshot and restore helpers."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return proc.returncode, out
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 1, f"Timed out: {' '.join(cmd)}"


@dataclass
class InterfaceSnapshot:
    name: str
    operstate: str = "?"
    mode: str = ""
    addresses: list[str] = field(default_factory=list)
    nm_managed: Optional[bool] = None
    nm_connection: str = ""
    nm_was_running: Optional[bool] = None


def read_operstate(name: str) -> str:
    path = Path(f"/sys/class/net/{name}/operstate")
    if not path.exists():
        return "?"
    try:
        return path.read_text(encoding="utf-8").strip() or "?"
    except OSError:
        return "?"


def read_mode(name: str) -> str:
    iw = shutil.which("iw")
    if not iw:
        return ""
    code, out = _run([iw, "dev", name, "info"], timeout=10)
    if code != 0:
        return ""
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("type "):
            return stripped.split(None, 1)[1]
    return ""


def read_addresses(name: str) -> list[str]:
    ip = shutil.which("ip")
    if not ip:
        return []
    code, out = _run([ip, "-br", "addr", "show", "dev", name], timeout=10)
    if code != 0 or not out.strip():
        return []
    parts = out.split()
    # Format: IFACE STATE ADDR1 ADDR2 ...
    return parts[2:] if len(parts) >= 3 else []


def nmcli_device_managed(name: str) -> Optional[bool]:
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return None
    code, out = _run([nmcli, "-g", "GENERAL.STATE", "device", "show", name], timeout=10)
    if code != 0:
        return None
    # Better: GENERAL.NM-MANAGED
    code2, out2 = _run([nmcli, "-g", "GENERAL.NM-MANAGED", "device", "show", name], timeout=10)
    if code2 != 0:
        return None
    return out2.strip().lower() in {"yes", "true", "1"}


def nmcli_active_connection(name: str) -> str:
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return ""
    code, out = _run(
        [nmcli, "-g", "GENERAL.CONNECTION", "device", "show", name],
        timeout=10,
    )
    if code != 0:
        return ""
    value = out.strip()
    return "" if value in {"", "--"} else value


def nm_is_running() -> Optional[bool]:
    systemctl = shutil.which("systemctl")
    if systemctl:
        code, _ = _run([systemctl, "is-active", "--quiet", "NetworkManager"], timeout=10)
        return code == 0
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return None
    code, _ = _run([nmcli, "general", "status"], timeout=10)
    return code == 0


def snapshot_interface(name: str) -> InterfaceSnapshot:
    return InterfaceSnapshot(
        name=name,
        operstate=read_operstate(name),
        mode=read_mode(name),
        addresses=read_addresses(name),
        nm_managed=nmcli_device_managed(name),
        nm_connection=nmcli_active_connection(name),
        nm_was_running=nm_is_running(),
    )


def disconnect_interface(name: str) -> None:
    """Disconnect the adapter from any active NetworkManager Wi-Fi connection."""
    nmcli = shutil.which("nmcli")
    if not nmcli or not name:
        return
    _run([nmcli, "device", "disconnect", name], timeout=20)


def rfkill_unblock() -> None:
    """Best-effort: clear any soft rfkill block that would stop the AP coming up."""
    rfkill = shutil.which("rfkill")
    if not rfkill:
        return
    _run([rfkill, "unblock", "wifi"], timeout=10)
    _run([rfkill, "unblock", "wlan"], timeout=10)


def stop_interfering_processes(iface: str) -> list[int]:
    """
    Stop only the wpa_supplicant instances bound to *this* interface.

    A wpa_supplicant still holding the adapter is the most common reason
    hostapd fails to start. We target processes whose command line references
    both ``wpa_supplicant`` and the specific interface name, so unrelated
    system daemons are never touched. Returns the PIDs we signalled.
    """
    if not iface:
        return []
    killed: list[int] = []
    proc_root = "/proc"
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return killed
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"{proc_root}/{entry}/cmdline", "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")
        if "wpa_supplicant" in cmdline and iface in cmdline.split():
            pid = int(entry)
            if pid == os.getpid():
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                killed.append(pid)
            except OSError:
                pass
    return killed


def set_nm_managed(name: str, managed: bool) -> None:
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return
    _run(
        [nmcli, "device", "set", name, "managed", "yes" if managed else "no"],
        timeout=20,
    )


def restore_interface(snapshot: InterfaceSnapshot) -> None:
    """Best-effort restore. Safe to call multiple times."""
    name = snapshot.name
    if not name:
        return

    ip = shutil.which("ip")
    iw = shutil.which("iw")

    if ip:
        _run([ip, "link", "set", name, "down"], timeout=15)

    if iw:
        # Return to managed/station mode when possible.
        _run([iw, "dev", name, "set", "type", "managed"], timeout=15)

    if ip:
        _run([ip, "addr", "flush", "dev", name], timeout=15)
        for addr in snapshot.addresses:
            # Restore CIDR addresses previously observed.
            if "/" in addr:
                _run([ip, "addr", "add", addr, "dev", name], timeout=15)
        if snapshot.operstate == "up":
            _run([ip, "link", "set", name, "up"], timeout=15)
        else:
            # Leave down unless it was up; still bring up if NM will manage it.
            if snapshot.nm_managed:
                _run([ip, "link", "set", name, "up"], timeout=15)

    if snapshot.nm_managed is True:
        set_nm_managed(name, True)
    elif snapshot.nm_managed is False:
        set_nm_managed(name, False)

    nmcli = shutil.which("nmcli")
    if nmcli and snapshot.nm_connection:
        _run([nmcli, "connection", "up", snapshot.nm_connection], timeout=30)
