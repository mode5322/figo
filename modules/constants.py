"""Shared constants and project paths."""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "figo"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENTRY_SCRIPT = PROJECT_ROOT / "figo.py"
TOOL_DIR = PROJECT_ROOT
DEFAULT_HANDSHAKE_DIR = str(TOOL_DIR / "handshakes")
CAPTURE_TIMEOUT_SEC = 90
DEAUTH_COUNT = 5
DEAUTH_BURSTS = 8
DEAUTH_GAP_SEC = 8
AIRODUMP_WARMUP_SEC = 4
STATION_SCAN_SEC = 6
TOOL_PACKAGES = {
    "airmon-ng": "aircrack-ng",
    "airodump-ng": "aircrack-ng",
    "aireplay-ng": "aircrack-ng",
    "aircrack-ng": "aircrack-ng",
    "cowpatty": "cowpatty",
    "iw": "iw",
    "nmcli": "network-manager",
    "hashcat": "hashcat",
    "hcxpcapngtool": "hcxtools",
    "hostapd": "hostapd",
    "dnsmasq": "dnsmasq",
    "ip": "iproute2",
}
REQUIRED_BINS = ("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng")
OPTIONAL_BINS = (
    "cowpatty",
    "iw",
    "nmcli",
    "hashcat",
    "hcxpcapngtool",
    "hostapd",
    "dnsmasq",
    "ip",
)


def effective_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        home = Path("/home") / sudo_user
        if home.is_dir():
            return home
    return Path.home()


CONFIG_DIR = effective_home() / ".config" / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"
COMMON_WORDLIST_DIRS = [
    Path("/usr/share/wordlists"),
    Path("/usr/share/seclists/Passwords"),
    effective_home() / "wordlists",
]
