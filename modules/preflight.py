"""Preflight checks and wireless adapter capability probes."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from typing import Optional

from modules.network import wireless_interfaces
from modules.tools import missing_bins, run_cmd, which_or_none


@dataclass
class AdapterCapabilities:
    name: str
    exists: bool = False
    current_mode: str = ""
    supports_monitor: Optional[bool] = None
    supports_ap: Optional[bool] = None
    supports_managed: Optional[bool] = None
    phy: str = ""
    notes: list[str] = field(default_factory=list)

    def summary_line(self) -> str:
        def mark(val: Optional[bool]) -> str:
            if val is True:
                return "yes"
            if val is False:
                return "no"
            return "?"

        return (
            f"{self.name}: mode={self.current_mode or '?'} · "
            f"monitor={mark(self.supports_monitor)} · "
            f"AP={mark(self.supports_ap)} · "
            f"managed={mark(self.supports_managed)}"
        )


@dataclass
class PreflightItem:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class PreflightReport:
    mode: str
    items: list[PreflightItem] = field(default_factory=list)
    adapter: Optional[AdapterCapabilities] = None

    @property
    def ok(self) -> bool:
        return all(item.ok for item in self.items)

    def blocking_failures(self) -> list[PreflightItem]:
        return [item for item in self.items if not item.ok]


def _iface_type(name: str) -> str:
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


def _phy_for_iface(name: str) -> str:
    link = f"/sys/class/net/{name}/phy80211"
    try:
        import os

        if os.path.islink(link) or os.path.exists(link):
            return os.path.basename(os.path.realpath(link))
    except OSError:
        pass
    iw = which_or_none("iw")
    if not iw:
        return ""
    code, out = run_cmd([iw, "dev", name, "info"], timeout=10)
    if code != 0:
        return ""
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("wiphy "):
            # "wiphy 0" → phy0
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return f"phy{parts[1]}"
    return ""


def probe_adapter_capabilities(iface: str) -> AdapterCapabilities:
    """Non-destructive capability probe using iw phy info."""
    caps = AdapterCapabilities(name=iface)
    ifaces = wireless_interfaces()
    caps.exists = iface in ifaces or bool(iface)
    if not iface:
        caps.notes.append("No interface selected.")
        return caps
    if iface not in ifaces:
        # Still try; interface may exist without wireless sysfs mark
        pass
    path = f"/sys/class/net/{iface}"
    if not os.path.exists(path):
        caps.exists = False
        caps.notes.append(f"Interface {iface} not found.")
        return caps
    caps.exists = True
    caps.current_mode = _iface_type(iface) or "?"
    caps.phy = _phy_for_iface(iface)

    iw = which_or_none("iw")
    if not iw:
        caps.notes.append("iw not installed — cannot probe AP/monitor support.")
        return caps

    phy = caps.phy
    out = ""
    if phy:
        _code, out = run_cmd([iw, "phy", phy, "info"], timeout=15)
    if not out:
        _code, out = run_cmd([iw, "list"], timeout=15)

    modes: set[str] = set()
    in_modes = False
    for line in out.splitlines():
        stripped = line.strip()
        if "Supported interface modes" in stripped:
            in_modes = True
            continue
        if in_modes:
            if stripped.startswith("*"):
                modes.add(stripped.lstrip("* ").strip().lower())
            elif stripped and not stripped.startswith("*"):
                # end of modes block when indentation drops to a new section
                if not line.startswith("\t\t") and not line.startswith("    "):
                    in_modes = False

    if modes:
        caps.supports_monitor = "monitor" in modes
        caps.supports_ap = "ap" in modes or any(m == "ap" or m.startswith("ap/") for m in modes)
        caps.supports_managed = "managed" in modes or "station" in modes
    else:
        caps.notes.append("Could not parse supported interface modes from iw.")
    return caps


def _port_in_use(port: int, host: str = "0.0.0.0") -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        return False
    except OSError:
        return True
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _udp_port_likely_busy(port: int = 53) -> Optional[bool]:
    """Best-effort: try binding UDP; None if inconclusive."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    finally:
        try:
            sock.close()
        except OSError:
            pass


def run_preflight(
    *,
    mode: str,
    interface: str = "",
    required_bins: tuple[str, ...] = (),
    portal_port: int = 8080,
    check_ap: bool = False,
    check_monitor: bool = False,
    check_dns_port: bool = False,
    require_root: bool = False,
) -> PreflightReport:
    """
    mode: capture | crack | lab | awareness
    """
    report = PreflightReport(mode=mode)

    if require_root:
        report.items.append(
            PreflightItem(
                "root",
                os.geteuid() == 0,
                "Root is required for this action." if os.geteuid() != 0 else "Running as root.",
            )
        )

    if required_bins:
        missing = missing_bins(required_bins)
        report.items.append(
            PreflightItem(
                "tools",
                not missing,
                ("Missing: " + ", ".join(missing)) if missing else "Required tools present.",
            )
        )

    if interface:
        caps = probe_adapter_capabilities(interface)
        report.adapter = caps
        report.items.append(
            PreflightItem(
                "interface",
                caps.exists,
                caps.summary_line() if caps.exists else f"Interface not found: {interface}",
            )
        )
        if check_monitor and caps.supports_monitor is False:
            report.items.append(
                PreflightItem(
                    "monitor capability",
                    False,
                    f"{interface} does not advertise monitor mode.",
                )
            )
        elif check_monitor and caps.supports_monitor is True:
            report.items.append(
                PreflightItem("monitor capability", True, f"{interface} supports monitor mode.")
            )
        if check_ap and caps.supports_ap is False:
            report.items.append(
                PreflightItem(
                    "AP capability",
                    False,
                    f"{interface} does not advertise AP mode (Evil Twin needs AP support).",
                )
            )
        elif check_ap and caps.supports_ap is True:
            report.items.append(
                PreflightItem("AP capability", True, f"{interface} supports AP mode.")
            )

    if check_dns_port:
        busy = _udp_port_likely_busy(53)
        if busy is True:
            report.items.append(
                PreflightItem(
                    "DNS port 53",
                    False,
                    "UDP/53 appears busy (dnsmasq may fail). Stop conflicting DNS or use another host.",
                )
            )
        elif busy is False:
            report.items.append(PreflightItem("DNS port 53", True, "UDP/53 appears free."))

    if portal_port and mode in {"lab", "awareness"}:
        busy = _port_in_use(int(portal_port))
        report.items.append(
            PreflightItem(
                f"portal port {portal_port}",
                not busy,
                (
                    f"TCP/{portal_port} is in use."
                    if busy
                    else f"TCP/{portal_port} appears free."
                ),
            )
        )

    nm = which_or_none("nmcli")
    if nm and mode in {"capture", "lab", "awareness"}:
        report.items.append(
            PreflightItem(
                "NetworkManager",
                True,
                "nmcli present — Figo will unmanage/restart NM around lab/capture as needed.",
            )
        )

    return report


def format_preflight_report(report: PreflightReport) -> str:
    ifaces = wireless_interfaces()
    adapter_count = len(ifaces)
    lines: list[str] = [
        f"Preflight · {report.mode}",
        f"Wireless adapters: {adapter_count}"
        + (f"  →  {', '.join(ifaces)}" if ifaces else "  →  (none detected)"),
    ]
    if adapter_count < 2:
        lines.append(
            "[orange3]Note: disconnecting employees from the real AP (deauth) "
            "requires a second wireless adapter.[/orange3]"
        )
    elif adapter_count >= 2:
        lines.append(
            "[dim]Two or more adapters — deauth toward the real AP is available "
            "during Security Awareness Lab.[/dim]"
        )
    for item in report.items:
        mark = "[green]OK[/green]" if item.ok else "[red]FAIL[/red]"
        lines.append(f"{mark}  {item.name}: {item.detail}")
    if report.adapter and report.adapter.notes:
        for note in report.adapter.notes:
            lines.append(f"[dim]note[/dim]  {note}")
    return "\n".join(lines)
