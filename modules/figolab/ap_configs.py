"""hostapd / dnsmasq configuration builders for controlled lab AP."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from modules.figolab.lab_config import LabConfig


def build_hostapd_conf(config: "LabConfig", conf_path: Path) -> Path:
    """
    Build the lab AP config.

    Two link-layer modes are supported:

    * ``open`` (default) — no passphrase. Simplest to join, but clients show an
      "insecure / open network" warning.
    * ``wpa2`` — WPA2-PSK using a lab passphrase the administrator sets and
      shares with authorized participants. This makes the network appear
      "secured" (padlock) and more credible for the awareness assessment. The
      passphrase is the lab AP's OWN key — it is never a harvested credential.
    """
    iface = config.ap_interface or config.interface
    ssid = config.effective_ssid()
    channel = str(config.channel).strip()
    lines = [
        f"interface={iface}",
        "driver=nl80211",
        f"ssid={ssid}",
        "hw_mode=g" if _is_24ghz(channel) else "hw_mode=a",
        f"channel={channel}",
        "auth_algs=1",
        "ignore_broadcast_ssid=0",
    ]
    if getattr(config, "is_secured", None) and config.is_secured() and config.ap_passphrase:
        lines += [
            "wpa=2",
            f"wpa_passphrase={config.ap_passphrase}",
            "wpa_key_mgmt=WPA-PSK",
            "wpa_pairwise=CCMP",
            "rsn_pairwise=CCMP",
        ]
    else:
        lines.append("wpa=0")
    lines.append("")
    conf_path.write_text("\n".join(lines), encoding="utf-8")
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


def parse_dhcp_leases(leases_path: Path) -> list[dict[str, str]]:
    """
    Parse a dnsmasq lease file into structured client records.

    Each active line looks like:
        <expiry-epoch> <mac> <ip> <hostname|*> <client-id|*>

    Returns a list of {"mac", "ip", "hostname"} dicts (hostname "" when unknown).
    Never raises; returns [] on any error.
    """
    clients: list[dict[str, str]] = []
    if not leases_path.exists():
        return clients
    try:
        for line in leases_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            mac = parts[1]
            ip = parts[2]
            hostname = parts[3] if len(parts) >= 4 and parts[3] != "*" else ""
            clients.append({"mac": mac, "ip": ip, "hostname": hostname})
    except OSError:
        return []
    return clients


def count_dhcp_leases(leases_path: Path) -> int:
    return len(parse_dhcp_leases(leases_path))
