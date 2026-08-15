"""Tests for preflight, dry-run, and lab event log helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from modules.figolab.awareness.metrics import MetricsStore
from modules.figolab.lab_session import dry_run_lab_configs
from modules.figolab.models import LabConfig, normalize_lab_network, validate_portal_port
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
    assert "password" not in str(snap).lower()


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
