"""Unit tests for Figo Evil Twin Lab (no Wi-Fi hardware required)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.figolab.ap import build_dnsmasq_conf, build_hostapd_conf
from modules.figolab.awareness.metrics import (
    MetricsStore,
    assert_no_sensitive_payload,
    safe_record_interaction,
)
from modules.figolab.awareness.session import SessionStore, new_session_id
from modules.figolab.lab_session import LabSession, cleanup_lab_session, detect_lab_dependencies
from modules.figolab.models import (
    LabConfig,
    PortalConfig,
    channel_band,
    normalize_lab_network,
    validate_channel,
    validate_lab_network,
    validate_ssid,
)
from modules.figolab.processes import ProcessTracker


def test_validate_ssid():
    assert validate_ssid("OfficeWiFi")[0] is True
    assert validate_ssid("")[0] is False
    assert validate_ssid("<hidden>")[0] is False
    assert validate_ssid("x" * 33)[0] is False


def test_validate_channel_and_band():
    assert validate_channel("6")[0] is True
    assert validate_channel("36")[0] is True
    assert validate_channel("nope")[0] is False
    assert channel_band("6") == "2.4 GHz"
    assert channel_band("36") == "5 GHz"


def test_lab_config_validation():
    cfg = LabConfig(target_ssid="LabNet", channel="6", interface="wlan0", lab_mode="awareness")
    ok, err = cfg.validate()
    assert ok, err
    bad = LabConfig(target_ssid="", channel="6", interface="wlan0")
    assert bad.validate()[0] is False


def test_lab_network_presets_and_validation():
    default = normalize_lab_network({"preset": "default"})
    assert default["gateway_ip"] == "10.66.66.1"
    home = normalize_lab_network({"preset": "home"})
    assert home["gateway_ip"] == "192.168.1.1"
    assert home["dhcp_range_start"] == "192.168.1.10"
    assert validate_lab_network("10.66.66.1", "10.66.66.10", "10.66.66.100")[0] is True
    assert validate_lab_network("192.168.1.1", "192.168.1.10", "192.168.1.100")[0] is True
    # Gateway inside DHCP range
    assert validate_lab_network("10.66.66.50", "10.66.66.10", "10.66.66.100")[0] is False
    # Different subnet
    assert validate_lab_network("10.66.66.1", "192.168.1.10", "192.168.1.100")[0] is False
    custom = normalize_lab_network(
        {
            "preset": "custom",
            "gateway_ip": "10.99.0.1",
            "dhcp_range_start": "10.99.0.20",
            "dhcp_range_end": "10.99.0.50",
        }
    )
    assert custom["preset"] == "custom"
    assert custom["gateway_ip"] == "10.99.0.1"


def test_dnsmasq_uses_custom_gateway(tmp_path: Path):
    cfg = LabConfig(
        target_ssid="ExampleNetwork",
        channel="6",
        interface="wlan0",
        ap_interface="wlan0",
        gateway_ip="192.168.1.1",
        dhcp_range_start="192.168.1.10",
        dhcp_range_end="192.168.1.100",
    )
    leases = tmp_path / "leases"
    dnsmasq = build_dnsmasq_conf(cfg, tmp_path / "dnsmasq.conf", leases_path=leases)
    dtext = dnsmasq.read_text(encoding="utf-8")
    assert "192.168.1.1" in dtext
    assert "192.168.1.10,192.168.1.100" in dtext
    assert validate_lab_network(cfg.gateway_ip, cfg.dhcp_range_start, cfg.dhcp_range_end)[0]


def test_portal_config_roundtrip():
    portal = PortalConfig(organization="Acme", training_value="TRAIN-ONLY")
    raw = portal.to_dict()
    restored = PortalConfig.from_dict(raw)
    assert restored.organization == "Acme"
    assert restored.training_value == "TRAIN-ONLY"


def test_hostapd_and_dnsmasq_generation(tmp_path: Path):
    cfg = LabConfig(
        target_ssid="ExampleNetwork",
        channel="6",
        interface="wlan0",
        ap_interface="wlan0",
        gateway_ip="10.66.66.1",
    )
    hostapd = build_hostapd_conf(cfg, tmp_path / "hostapd.conf")
    text = hostapd.read_text(encoding="utf-8")
    assert "ssid=ExampleNetwork" in text
    assert "wpa=0" in text
    assert "channel=6" in text

    leases = tmp_path / "leases"
    dnsmasq = build_dnsmasq_conf(cfg, tmp_path / "dnsmasq.conf", leases_path=leases)
    dtext = dnsmasq.read_text(encoding="utf-8")
    assert "interface=wlan0" in dtext
    assert "10.66.66.1" in dtext


def test_dependency_detection_mock():
    with patch("modules.figolab.lab_session.shutil.which", side_effect=lambda n: None if n == "hostapd" else f"/usr/bin/{n}"):
        missing = detect_lab_dependencies()
    assert "hostapd" in missing


def test_session_create_and_expire(monkeypatch):
    store = SessionStore(ttl_sec=60)
    s = store.create()
    assert store.get(s.session_id) is not None
    assert len(new_session_id()) >= 16
    # Force expiry
    s.expires_at = 0
    assert store.get(s.session_id) is None


def test_metrics_and_credential_safety():
    metrics = MetricsStore()
    sid = "abc123"
    safe_record_interaction(metrics, sid)
    snap = metrics.snapshot()
    assert snap["interactions"] == 1
    # The submitted secret VALUE must never appear anywhere in the snapshot.
    # (Boolean/counter field names like "entered_password" are allowed.)
    assert "hunter2-secret" not in json.dumps(snap).lower()

    with pytest.raises(ValueError):
        assert_no_sensitive_payload({"password": "secret"})

    # Submitted values must never be retained
    result = safe_record_interaction(
        metrics,
        sid,
        submitted_value="real-looking-secret",
        expected_training_value="TRAIN",
    )
    assert result["training_action"] is False
    assert "real-looking-secret" not in json.dumps(result)
    assert "real-looking-secret" not in metrics.export_json()

    matched = safe_record_interaction(
        metrics,
        "sid2",
        submitted_value="TRAIN",
        expected_training_value="TRAIN",
    )
    assert matched["training_action"] is True
    assert "TRAIN" not in json.dumps(matched)


def test_process_tracker_terminate():
    tracker = ProcessTracker()
    proc = MagicMock()
    proc.poll.side_effect = [None, None, 0]
    proc.send_signal = MagicMock()
    proc.kill = MagicMock()
    proc.wait = MagicMock()
    tracker.track("dummy", proc)
    tracker.terminate_all(grace_sec=0.01)
    assert tracker.items == []


def test_cleanup_idempotent(tmp_path: Path):
    session = LabSession(config=LabConfig(interface="wlan0", channel="1", target_ssid="x"))
    session.temp_dir = tmp_path / "figo-lab-test"
    session.temp_dir.mkdir()
    (session.temp_dir / "hostapd.conf").write_text("x", encoding="utf-8")
    session.tracker = ProcessTracker()
    with patch("modules.figolab.lab_session.restore_interface"):
        cleanup_lab_session(session)
        cleanup_lab_session(session)  # second call must not raise
    assert not session.temp_dir.exists()


def test_settings_persistence_backward_compatible(tmp_path: Path, monkeypatch):
    import modules.config as config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / ".config" / "figo")
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / ".config" / "figo" / "config.json")

    # Old config without portal key
    config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config.CONFIG_FILE.write_text(
        json.dumps(
            {
                "interface": "wlan0",
                "wordlist": "",
                "handshake_dir": "",
                "target": {"ssid": "A"},
            }
        ),
        encoding="utf-8",
    )
    settings = config.load_settings()
    assert settings.interface == "wlan0"
    assert isinstance(settings.portal, dict)
    assert isinstance(settings.lab_network, dict)

    settings.portal = PortalConfig(organization="Org").to_dict()
    settings.lab_network = normalize_lab_network({"preset": "home"})
    config.save_settings(settings)
    reloaded = config.load_settings()
    assert reloaded.portal.get("organization") == "Org"
    assert reloaded.lab_network.get("gateway_ip") == "192.168.1.1"


def test_landing_template_has_no_password_field():
    from modules.figolab.awareness.templates import landing_page

    html = landing_page(
        ssid="ExampleNetwork",
        title="SECURITY AWARENESS TEST",
        organization="Acme",
        training_message="Verify credentials with IT",
        contact="security@example.com",
    )
    assert "type=\"password\"" not in html.lower()
    assert "ExampleNetwork" in html
    assert "never asks for or stores your real password" in html.lower()
