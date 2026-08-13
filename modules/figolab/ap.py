"""hostapd / dnsmasq configuration builders for controlled lab AP."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from modules.figolab.models import LabConfig


def build_hostapd_conf(config: "LabConfig", conf_path: Path) -> Path:
    """
    Build an open lab AP config (no WPA passphrase).

    The lab intentionally uses an open AP so participants are not asked for
    real Wi-Fi passwords at association time. Awareness happens in the portal.
    """
    iface = config.ap_interface or config.interface
    ssid = config.effective_ssid()
    channel = str(config.channel).strip()
    body = "\n".join(
        [
            f"interface={iface}",
            "driver=nl80211",
            f"ssid={ssid}",
            "hw_mode=g" if _is_24ghz(channel) else "hw_mode=a",
            f"channel={channel}",
            "auth_algs=1",
            "ignore_broadcast_ssid=0",
            "wpa=0",
            "",
        ]
    )
    conf_path.write_text(body, encoding="utf-8")
    return conf_path


def build_dnsmasq_conf(config: "LabConfig", conf_path: Path, *, leases_path: Path) -> Path:
    iface = config.ap_interface or config.interface
    portal_ip = config.gateway_ip
    body = "\n".join(
        [
            f"interface={iface}",
            "bind-interfaces",
            f"dhcp-range={config.dhcp_range_start},{config.dhcp_range_end},12h",
            f"dhcp-option=3,{portal_ip}",
            f"dhcp-option=6,{portal_ip}",
            f"address=/#/{portal_ip}",
            f"dhcp-leasefile={leases_path}",
            "log-queries",
            "log-dhcp",
            "",
        ]
    )
    conf_path.write_text(body, encoding="utf-8")
    return conf_path


def _is_24ghz(channel: str) -> bool:
    try:
        return 1 <= int(channel) <= 14
    except ValueError:
        return True


def count_dhcp_leases(leases_path: Path) -> int:
    if not leases_path.exists():
        return 0
    try:
        lines = [ln for ln in leases_path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
        return len(lines)
    except OSError:
        return 0
