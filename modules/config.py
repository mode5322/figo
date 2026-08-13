"""Settings persistence."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Optional

from modules.constants import CONFIG_DIR, CONFIG_FILE, DEFAULT_HANDSHAKE_DIR


@dataclass
class Target:
    ssid: str = ""
    bssid: str = ""
    channel: str = ""
    signal: str = ""
    security: str = ""


@dataclass
class Settings:
    interface: str = ""
    wordlist: str = ""
    handshake_dir: str = DEFAULT_HANDSHAKE_DIR
    target: Target = field(default_factory=Target)
    portal: dict = field(default_factory=dict)


def load_settings() -> Settings:
    if not CONFIG_FILE.exists():
        return Settings()
    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        target_raw = raw.get("target", {}) or {}
        target = Target(
            ssid=str(target_raw.get("ssid", "") or ""),
            bssid=str(target_raw.get("bssid", "") or ""),
            channel=str(target_raw.get("channel", "") or ""),
            signal=str(target_raw.get("signal", "") or ""),
            security=str(target_raw.get("security", "") or ""),
        )
        portal_raw = raw.get("portal", {}) or {}
        if not isinstance(portal_raw, dict):
            portal_raw = {}
        return Settings(
            interface=raw.get("interface", ""),
            wordlist=raw.get("wordlist", ""),
            handshake_dir=raw.get("handshake_dir") or DEFAULT_HANDSHAKE_DIR,
            target=target,
            portal=portal_raw,
        )
    except (OSError, json.JSONDecodeError, TypeError):
        return Settings()


def save_settings(settings: Settings) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    portal = settings.portal
    if hasattr(portal, "to_dict"):
        portal = portal.to_dict()
    elif not isinstance(portal, dict):
        portal = {}
    payload = {
        "interface": settings.interface,
        "wordlist": settings.wordlist,
        "handshake_dir": settings.handshake_dir or DEFAULT_HANDSHAKE_DIR,
        "target": asdict(settings.target),
        "portal": portal,
    }
    CONFIG_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
