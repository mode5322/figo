"""Tests for preflight, dry-run, and lab event log helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from modules.figolab.ap import build_hostapd_conf
from modules.figolab.awareness import templates
from modules.figolab.awareness.metrics import MetricsStore
from modules.figolab.awareness.portal import CAPTIVE_PORT
from modules.figolab.lab_session import dry_run_lab_configs
from modules.figolab.models import (
    LabConfig,
    normalize_lab_network,
    validate_ap_passphrase,
    validate_portal_port,
)
from modules.preflight import AdapterCapabilities, format_preflight_report, probe_adapter_capabilities, run_preflight
from modules.tools import packages_for


def test_normalize_lab_network_includes_port_and_ssid():
    custom = normalize_lab_network(
        {
            "preset": "custom",
            "gateway_ip": "10.99.0.1",
            "dhcp_range_start": "10.99.0.20",
            "dhcp_range_end": "10.99.0.50",
            "subnet_prefix": "24",
            "portal_port": "9090",
            "ap_ssid": "LabWiFi-Training",
        }
    )
    assert custom["portal_port"] == "9090"
    assert custom["ap_ssid"] == "LabWiFi-Training"
    assert validate_portal_port(9090)[0] is True
    assert validate_portal_port(70000)[0] is False


def test_packages_for_skips_nvidia_stack():
    # Even if a bin somehow mapped oddly, nvidia packages must not be installed by Figo.
    pkgs = packages_for(["hashcat", "iw"])
    assert "hashcat" in pkgs
    assert all(not p.lower().startswith("nvidia") for p in pkgs)


def test_metrics_event_log_and_client_delta():
    store = MetricsStore()
    store.mark_portal_opened("abcdef123456")
    store.mark_interaction("abcdef123456")
    store.set_connected_devices(2)
    store.set_connected_devices(1)
    events = store.recent_events(10)
    kinds = [e["kind"] for e in events]
    assert "portal" in kinds
    assert "interact" in kinds
    assert "client" in kinds
    snap = store.snapshot()
    assert "events" in snap
    # Counters exist, but no submitted secret value is ever retained.
    assert "login_submissions" in snap
    assert "passwords_entered" in snap


def test_dry_run_lab_configs(tmp_path: Path):
    cfg = LabConfig(
        target_ssid="Office",
        ap_ssid="Office-Lab",
        channel="6",
        interface="wlan0",
        ap_interface="wlan0",
        gateway_ip="10.66.66.1",
        dhcp_range_start="10.66.66.10",
        dhcp_range_end="10.66.66.100",
        subnet_prefix=24,
        portal_port=8080,
    )
    hostapd_text, dnsmasq_text, notes = dry_run_lab_configs(cfg)
    assert "ssid=Office-Lab" in hostapd_text
    assert "10.66.66.1" in dnsmasq_text
    assert "Office-Lab" in notes


def test_probe_adapter_capabilities_parses_iw_list():
    sample = """
Wiphy phy0
	Supported interface modes:
		 * managed
		 * AP
		 * monitor
	Band 1:
"""
    with patch("modules.preflight.wireless_interfaces", return_value=["wlan0"]):
        with patch("modules.preflight.os.path.exists", return_value=True):
            with patch("modules.preflight.which_or_none", return_value="/usr/sbin/iw"):
                with patch("modules.preflight.run_cmd", return_value=(0, sample)):
                    with patch("modules.preflight._phy_for_iface", return_value="phy0"):
                        with patch("modules.preflight._iface_type", return_value="managed"):
                            caps = probe_adapter_capabilities("wlan0")
    assert caps.supports_ap is True
    assert caps.supports_monitor is True
    assert "AP=yes" in caps.summary_line()


def test_run_preflight_missing_tools():
    with patch("modules.preflight.missing_bins", return_value=["hostapd"]):
        with patch("modules.preflight.probe_adapter_capabilities", return_value=AdapterCapabilities(name="wlan0", exists=True)):
            report = run_preflight(
                mode="lab",
                interface="wlan0",
                required_bins=("hostapd",),
                check_ap=False,
            )
    assert report.ok is False
    text = format_preflight_report(report)
    assert "hostapd" in text


def test_hostapd_open_vs_wpa2(tmp_path: Path):
    base = dict(
        target_ssid="Office",
        ap_ssid="Office-Lab",
        channel="6",
        interface="wlan0",
        ap_interface="wlan0",
    )
    open_cfg = LabConfig(ap_security="open", **base)
    open_path = tmp_path / "open.conf"
    build_hostapd_conf(open_cfg, open_path)
    open_text = open_path.read_text()
    assert "wpa=0" in open_text
    assert "wpa_passphrase" not in open_text

    secure_cfg = LabConfig(ap_security="wpa2", ap_passphrase="LabPass1234", **base)
    secure_path = tmp_path / "secure.conf"
    build_hostapd_conf(secure_cfg, secure_path)
    secure_text = secure_path.read_text()
    assert "wpa=2" in secure_text
    assert "wpa_passphrase=LabPass1234" in secure_text
    assert "wpa_key_mgmt=WPA-PSK" in secure_text


def test_ap_passphrase_and_network_security_normalization():
    assert validate_ap_passphrase("short")[0] is False
    assert validate_ap_passphrase("LongEnough123")[0] is True
    secured = normalize_lab_network({"preset": "default", "ap_security": "wpa2", "ap_passphrase": "LabPass1234"})
    assert secured["ap_security"] == "wpa2"
    assert secured["ap_passphrase"] == "LabPass1234"
    # Switching back to open clears the stored passphrase.
    opened = normalize_lab_network({"preset": "default", "ap_security": "open", "ap_passphrase": "LabPass1234"})
    assert opened["ap_security"] == "open"
    assert opened["ap_passphrase"] == ""
    # wpa2 config fails validation without a passphrase.
    cfg = LabConfig(ap_ssid="Lab", channel="6", interface="wlan0", ap_security="wpa2", ap_passphrase="")
    assert cfg.validate()[0] is False


def test_login_page_has_password_field_and_posts_to_login():
    html = templates.login_page(
        ssid="CorpWiFi",
        title="Network sign-in",
        organization="Acme",
    )
    assert 'action="/login"' in html
    assert 'type="password"' in html
    assert "CorpWiFi" in html


def test_login_submission_records_behavior_not_password():
    store = MetricsStore()
    sid = "sessionabcdef"
    # entered_password True must bump the counter and set the flag, but the
    # actual value is never passed to the metrics store at all.
    store.mark_login_submitted(sid, entered_password=True)
    snap = store.snapshot()
    assert snap["login_submissions"] == 1
    assert snap["passwords_entered"] == 1
    session = store.get_session(sid)
    assert session.entered_password is True
    assert session.submitted_login is True
    kinds = [e["kind"] for e in store.recent_events(10)]
    assert "risk" in kinds


def test_result_page_lists_behaviors_and_warns_on_password():
    html = templates.result_page(
        title="Awareness",
        organization="Acme",
        educational_message="Never enter your password.",
        contact="soc@acme",
        behaviors=["Connected to the untrusted Wi-Fi network", "Typed a password into the sign-in page"],
        entered_password=True,
    )
    assert "Typed a password into the sign-in page" in html
    assert "NOT stored" in html


def test_captive_port_constant():
    assert CAPTIVE_PORT == 80


def test_connected_page_does_not_reveal_simulation():
    html = templates.connected_page(ssid="CorpWiFi", title="Wi-Fi Authentication", organization="Acme")
    low = html.lower()
    assert "connected" in low
    # The client-facing confirmation must not tip off the participant.
    for giveaway in ("simulation", "awareness", "this was a", "test", "phishing"):
        assert giveaway not in low
    assert "CorpWiFi" in html
