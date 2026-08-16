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


def validate_ipv4(ip: str) -> tuple[bool, str]:
    value = (ip or "").strip()
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
        return False, "IP must look like 192.168.1.1"
    parts = [int(p) for p in value.split(".")]
    if any(p < 0 or p > 255 for p in parts):
        return False, "Each IP octet must be 0–255."
    if parts[0] == 0 or parts[3] in {0, 255}:
        return False, "Gateway/host IP cannot use .0 or .255 as the last octet."
    return True, ""


def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(x) for x in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def same_slash24(a: str, b: str) -> bool:
    try:
        return _ip_to_int(a) >> 8 == _ip_to_int(b) >> 8
    except (TypeError, ValueError):
        return False


def validate_lab_network(
    gateway_ip: str,
    dhcp_range_start: str,
    dhcp_range_end: str,
) -> tuple[bool, str]:
    for label, value in (
        ("Gateway IP", gateway_ip),
        ("DHCP start", dhcp_range_start),
        ("DHCP end", dhcp_range_end),
    ):
        ok, err = validate_ipv4(value)
        if not ok:
            return False, f"{label}: {err}"
    gw = gateway_ip.strip()
    start = dhcp_range_start.strip()
    end = dhcp_range_end.strip()
    if not same_slash24(gw, start) or not same_slash24(gw, end):
        return False, "Gateway and DHCP range must be in the same /24 subnet."
    if _ip_to_int(start) > _ip_to_int(end):
        return False, "DHCP start must be less than or equal to DHCP end."
    gw_i = _ip_to_int(gw)
    if _ip_to_int(start) <= gw_i <= _ip_to_int(end):
        return False, "Gateway IP must not fall inside the DHCP range."
    return True, ""


LAB_NETWORK_PRESETS: dict[str, dict[str, str]] = {
    "default": {
        "preset": "default",
        "gateway_ip": "10.66.66.1",
        "dhcp_range_start": "10.66.66.10",
        "dhcp_range_end": "10.66.66.100",
        "subnet_prefix": "24",
        "portal_port": "8080",
        "ap_ssid": "",
        "ap_security": "open",
        "ap_passphrase": "",
    },
    "home": {
        "preset": "home",
        "gateway_ip": "192.168.1.1",
        "dhcp_range_start": "192.168.1.10",
        "dhcp_range_end": "192.168.1.100",
        "subnet_prefix": "24",
        "portal_port": "8080",
        "ap_ssid": "",
        "ap_security": "open",
        "ap_passphrase": "",
    },
}


def normalize_lab_network(raw: Optional[dict[str, Any]] = None) -> dict[str, str]:
    """Return a complete lab network dict; defaults to 10.66.66.x."""
    base = dict(LAB_NETWORK_PRESETS["default"])
    raw = raw or {}
    preset = str(raw.get("preset", "") or "").strip().lower()
    ap_security = str(raw.get("ap_security", "open") or "open").strip().lower()
    if ap_security not in AP_SECURITY_MODES:
        ap_security = "open"
    ap_passphrase = str(raw.get("ap_passphrase", "") or "")
    if ap_security != "wpa2":
        ap_passphrase = ""
    if preset in LAB_NETWORK_PRESETS and preset != "custom":
        merged = dict(LAB_NETWORK_PRESETS[preset])
        # Allow overriding port/ssid/security on top of a named preset.
        if raw.get("portal_port"):
            merged["portal_port"] = str(raw.get("portal_port"))
        if "ap_ssid" in raw:
            merged["ap_ssid"] = str(raw.get("ap_ssid") or "")
        if raw.get("subnet_prefix"):
            merged["subnet_prefix"] = str(raw.get("subnet_prefix"))
        merged["ap_security"] = ap_security
        merged["ap_passphrase"] = ap_passphrase
        return merged
    gateway = str(raw.get("gateway_ip", base["gateway_ip"]) or base["gateway_ip"]).strip()
    start = str(raw.get("dhcp_range_start", base["dhcp_range_start"]) or base["dhcp_range_start"]).strip()
    end = str(raw.get("dhcp_range_end", base["dhcp_range_end"]) or base["dhcp_range_end"]).strip()
    prefix = str(raw.get("subnet_prefix", base["subnet_prefix"]) or base["subnet_prefix"]).strip()
    port = str(raw.get("portal_port", base["portal_port"]) or base["portal_port"]).strip()
    ap_ssid = str(raw.get("ap_ssid", "") or "").strip()
    known = next(
        (
            name
            for name, preset_data in LAB_NETWORK_PRESETS.items()
            if preset_data["gateway_ip"] == gateway
            and preset_data["dhcp_range_start"] == start
            and preset_data["dhcp_range_end"] == end
            and not ap_ssid
            and prefix == "24"
            and port == "8080"
            and ap_security == "open"
        ),
        "custom",
    )
    return {
        "preset": known if preset != "custom" else "custom",
        "gateway_ip": gateway,
        "dhcp_range_start": start,
        "dhcp_range_end": end,
        "subnet_prefix": prefix or "24",
        "portal_port": port or "8080",
        "ap_ssid": ap_ssid,
        "ap_security": ap_security,
        "ap_passphrase": ap_passphrase,
    }


def validate_portal_port(port: str | int) -> tuple[bool, str]:
    try:
        value = int(str(port).strip())
    except (TypeError, ValueError):
        return False, "Portal port must be a number."
    if not (1 <= value <= 65535):
        return False, "Portal port must be 1–65535."
    return True, ""


def validate_subnet_prefix(prefix: str | int) -> tuple[bool, str]:
    try:
        value = int(str(prefix).strip())
    except (TypeError, ValueError):
        return False, "Subnet prefix must be a number."
    if not (8 <= value <= 30):
        return False, "Subnet prefix must be between 8 and 30."
    return True, ""


AP_SECURITY_MODES = {"open", "wpa2"}


def validate_ap_security(mode: str) -> tuple[bool, str]:
    value = (mode or "open").strip().lower()
    if value not in AP_SECURITY_MODES:
        return False, "AP security must be 'open' or 'wpa2'."
    return True, ""


def validate_ap_passphrase(passphrase: str) -> tuple[bool, str]:
    """Validate the lab AP's OWN WPA2 key (chosen by the admin, not harvested)."""
    value = passphrase or ""
    if not (8 <= len(value) <= 63):
        return False, "WPA2 passphrase must be 8–63 characters."
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in value):
        return False, "WPA2 passphrase must use printable ASCII characters."
    return True, ""


@dataclass
class PortalConfig:
    enabled: bool = True
    organization: str = ""
    # Client-facing title. Kept neutral on purpose so the sign-in page looks
    # like a real network portal — the participant should not realise it is a
    # simulation until the debrief / manual report.
    portal_title: str = "Wi-Fi Authentication"
    training_message: str = (
        "Please sign in with your network account to continue."
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
    # Show a realistic sign-in page with a password field. The submitted value
    # is NEVER stored, logged, or transmitted — only the behaviour is recorded.
    require_login: bool = True
    login_username_label: str = "Username / Email"
    login_password_label: str = "Wi-Fi / Network password"
    login_button_label: str = "Sign in"

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
            require_login=bool(raw.get("require_login", True)),
            login_username_label=str(
                raw.get("login_username_label", cls.login_username_label)
                or cls.login_username_label
            ),
            login_password_label=str(
                raw.get("login_password_label", cls.login_password_label)
                or cls.login_password_label
            ),
            login_button_label=str(
                raw.get("login_button_label", cls.login_button_label) or cls.login_button_label
            ),
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
    subnet_prefix: int = 24
    portal_port: int = 8080
    # Lab AP link-layer security. "open" (default) or "wpa2" with a lab
    # passphrase the admin sets and shares with authorized participants.
    ap_security: str = "open"
    ap_passphrase: str = ""
    # Optional authorized client-kick (deauth) against the *target* BSSID.
    # Requires a second wireless adapter in monitor mode while the lab AP
    # runs on `interface`. Off by default.
    kick_clients: bool = False
    kick_interface: str = ""

    def effective_ssid(self) -> str:
        return (self.ap_ssid or self.target_ssid or "").strip()

    def is_secured(self) -> bool:
        return (self.ap_security or "open").strip().lower() == "wpa2"

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
        ok, err = validate_lab_network(
            self.gateway_ip,
            self.dhcp_range_start,
            self.dhcp_range_end,
        )
        if not ok:
            return False, err
        ok, err = validate_subnet_prefix(self.subnet_prefix)
        if not ok:
            return False, err
        ok, err = validate_portal_port(self.portal_port)
        if not ok:
            return False, err
        ok, err = validate_ap_security(self.ap_security)
        if not ok:
            return False, err
        if self.is_secured():
            ok, err = validate_ap_passphrase(self.ap_passphrase)
            if not ok:
                return False, err
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
            subnet_prefix=int(raw.get("subnet_prefix", 24) or 24),
            portal_port=int(raw.get("portal_port", 8080) or 8080),
            ap_security=str(raw.get("ap_security", "open") or "open").strip().lower(),
            ap_passphrase=str(raw.get("ap_passphrase", "") or ""),
            kick_clients=bool(raw.get("kick_clients", False)),
            kick_interface=str(raw.get("kick_interface", "") or ""),
        )


LAB_BINS = ("hostapd", "dnsmasq", "iw", "ip")
LAB_PACKAGES = {
    "hostapd": "hostapd",
    "dnsmasq": "dnsmasq",
    "iw": "iw",
    "ip": "iproute2",
    "nmcli": "network-manager",
}
