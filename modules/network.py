"""Wireless interface discovery and network scanning."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional


def _signal_sort_key(row: dict[str, str]) -> int:
    try:
        return int(str(row.get("signal") or "0").strip())
    except (TypeError, ValueError):
        return 0


def wireless_interfaces() -> list[str]:
    ifaces: list[str] = []
    net = Path("/sys/class/net")
    if net.exists():
        for entry in sorted(net.iterdir()):
            if (entry / "wireless").exists() or (entry / "phy80211").exists():
                ifaces.append(entry.name)
    if ifaces:
        return ifaces

    iw = shutil.which("iw")
    if not iw:
        return []
    try:
        out = subprocess.check_output([iw, "dev"], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return []
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface "):
            current = stripped.split(None, 1)[1]
            if current:
                ifaces.append(current)
    return ifaces


def iface_state(name: str) -> str:
    oper = Path(f"/sys/class/net/{name}/operstate")
    if oper.exists():
        try:
            return oper.read_text(encoding="utf-8").strip()
        except OSError:
            return "?"
    return "?"


def nmcli_split(line: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    escaped = False
    for ch in line:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def scan_networks(interface: str) -> tuple[list[dict[str, str]], Optional[str]]:
    nmcli = shutil.which("nmcli")
    if nmcli:
        cmd = [
            nmcli,
            "-g",
            "SSID,BSSID,CHAN,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
            "ifname",
            interface,
            "--rescan",
            "yes",
        ]
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
            rows: list[dict[str, str]] = []
            seen: set[str] = set()
            for line in out.splitlines():
                if not line.strip():
                    continue
                parts = nmcli_split(line)
                if len(parts) < 5:
                    continue
                ssid, bssid, channel, signal, security = parts[:5]
                key = bssid.upper() or ssid
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "ssid": ssid or "<hidden>",
                        "bssid": bssid,
                        "channel": channel,
                        "signal": signal,
                        "security": security or "-",
                    }
                )
            rows.sort(key=_signal_sort_key, reverse=True)
            return rows, None
        except subprocess.CalledProcessError as exc:
            err = (exc.output or str(exc)).strip()
            return [], err or "Scan failed (nmcli)"
        except (OSError, ValueError) as exc:
            return [], f"Scan failed (nmcli): {exc}"

    iw = shutil.which("iw")
    if not iw:
        return [], "No scan tool available (nmcli or iw)"
    try:
        out = subprocess.check_output(
            [iw, "dev", interface, "scan"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        err = (exc.output or str(exc)).strip()
        return [], err or "Scan failed (iw). You may need elevated privileges."

    rows = []
    current: dict[str, str] = {}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("BSS ") and s[4:21].count(":") == 5:
            if current.get("bssid"):
                rows.append(current)
            bssid = s[4:21].split()[0]
            current = {
                "ssid": "<hidden>",
                "bssid": bssid,
                "channel": "-",
                "signal": "0",
                "security": "-",
            }
        elif s.startswith("SSID:"):
            ssid = s.split("SSID:", 1)[1].strip()
            current["ssid"] = ssid or "<hidden>"
        elif s.startswith("signal:"):
            try:
                dbm = float(s.split()[1])
                current["signal"] = str(max(0, min(100, int(2 * (dbm + 100)))))
            except (IndexError, ValueError):
                pass
        elif "DS Parameter set: channel" in s:
            current["channel"] = s.rsplit(" ", 1)[-1]
    if current.get("bssid"):
        rows.append(current)
    rows.sort(key=_signal_sort_key, reverse=True)
    return rows, None

