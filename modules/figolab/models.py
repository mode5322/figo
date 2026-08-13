"""Configuration models and validation for Evil Twin Lab."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

SSID_MAX_LEN = 32
VALID_CHANNELS = set(range(1, 15)) | set(range(36, 166))


def channel_band(channel: str | int) -> str:
    try:
        ch = int(str(channel).strip())
    except (TypeError, ValueError):
        return "unknown"
    if 1 <= ch <= 14:
        return "2.4 GHz"
    if ch >= 36:
        return "5 GHz"
    return "unknown"


def validate_ssid(ssid: str) -> tuple[bool, str]:
    value = (ssid or "").strip()
    if not value or value == "<hidden>":
        return False, "SSID is required and cannot be hidden for the lab AP."
    if len(value) > SSID_MAX_LEN:
        return False, f"SSID must be at most {SSID_MAX_LEN} characters."
    if "\x00" in value:
        return False, "SSID contains invalid characters."
    return True, ""


def validate_channel(channel: str | int) -> tuple[bool, str]:
    try:
        ch = int(str(channel).strip())
    except (TypeError, ValueError):
        return False, "Channel must be a number."
    if ch not in VALID_CHANNELS and not (1 <= ch <= 165):
        return False, f"Unsupported channel: {channel}"
    return True, ""


def validate_bssid(bssid: str) -> tuple[bool, str]:
    value = (bssid or "").strip()
    if not value:
        return False, "BSSID is required."
    if not re.fullmatch(r"(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}", value):
        return False, "BSSID must look like AA:BB:CC:DD:EE:FF."
    return True, ""


@dataclass
class PortalConfig:
    enabled: bool = True
    organization: str = ""
    portal_title: str = "SECURITY AWARENESS TEST"
    training_message: str = (
        "Before continuing, verify your network credentials with your IT team."
    )
    security_contact: str = ""
    educational_message: str = (
        "This was a controlled security-awareness simulation.\n"
        "The Wi-Fi network you connected to was part of an authorized security assessment.\n\n"
        "Important warning signs include:\n"
        "• Unexpected duplicate Wi-Fi networks\n"
        "• Suspicious login pages\n"
        "• Unexpected requests for credentials\n"
        "• Unusual network behavior\n\n"
        "Never enter your real password into an unexpected Wi-Fi authentication page.\n"
        "If you encounter a suspicious network, disconnect and contact your IT/security team."
    )
    training_value: str = ""
    logo_path: str = ""
    session_ttl_sec: int = 3600

    @classmethod
    def from_dict(cls, raw: Optional[dict[str, Any]]) -> "PortalConfig":
        raw = raw or {}
        return cls(
            enabled=bool(raw.get("enabled", True)),
            organization=str(raw.get("organization", "") or ""),
            portal_title=str(raw.get("portal_title", cls.portal_title) or cls.portal_title),
            training_message=str(
                raw.get("training_message", cls.training_message) or cls.training_message
            ),
            security_contact=str(raw.get("security_contact", "") or ""),
            educational_message=str(
                raw.get("educational_message", cls.educational_message)
                or cls.educational_message
            ),
            training_value=str(raw.get("training_value", "") or ""),
            logo_path=str(raw.get("logo_path", "") or ""),
            session_ttl_sec=int(raw.get("session_ttl_sec", 3600) or 3600),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LabConfig:
    target_ssid: str = ""
    target_bssid: str = ""
    channel: str = ""
    security: str = "open"
    interface: str = ""
    ap_interface: str = ""
    lab_mode: str = "awareness"  # wifi | awareness
    portal_enabled: bool = True
    portal: PortalConfig = field(default_factory=PortalConfig)
    ap_ssid: str = ""
    gateway_ip: str = "10.66.66.1"
    dhcp_range_start: str = "10.66.66.10"
    dhcp_range_end: str = "10.66.66.100"
    portal_port: int = 8080

    def effective_ssid(self) -> str:
        return (self.ap_ssid or self.target_ssid or "").strip()

    def validate(self) -> tuple[bool, str]:
        ok, err = validate_ssid(self.effective_ssid())
        if not ok:
            return False, err
        ok, err = validate_channel(self.channel)
        if not ok:
            return False, err
        if not self.interface.strip():
            return False, "Wireless interface is required."
        if self.lab_mode not in {"wifi", "awareness"}:
            return False, "Lab mode must be 'wifi' or 'awareness'."
        return True, ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data

    @classmethod
    def from_dict(cls, raw: Optional[dict[str, Any]]) -> "LabConfig":
        raw = raw or {}
        portal = PortalConfig.from_dict(raw.get("portal"))
        return cls(
            target_ssid=str(raw.get("target_ssid", "") or ""),
            target_bssid=str(raw.get("target_bssid", "") or ""),
            channel=str(raw.get("channel", "") or ""),
            security=str(raw.get("security", "open") or "open"),
            interface=str(raw.get("interface", "") or ""),
            ap_interface=str(raw.get("ap_interface", "") or ""),
            lab_mode=str(raw.get("lab_mode", "awareness") or "awareness"),
            portal_enabled=bool(raw.get("portal_enabled", True)),
            portal=portal,
            ap_ssid=str(raw.get("ap_ssid", "") or ""),
            gateway_ip=str(raw.get("gateway_ip", "10.66.66.1") or "10.66.66.1"),
            dhcp_range_start=str(raw.get("dhcp_range_start", "10.66.66.10") or "10.66.66.10"),
            dhcp_range_end=str(raw.get("dhcp_range_end", "10.66.66.100") or "10.66.66.100"),
            portal_port=int(raw.get("portal_port", 8080) or 8080),
        )


LAB_BINS = ("hostapd", "dnsmasq", "iw", "ip")
LAB_PACKAGES = {
    "hostapd": "hostapd",
    "dnsmasq": "dnsmasq",
    "iw": "iw",
    "ip": "iproute2",
    "nmcli": "network-manager",
}
