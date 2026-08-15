"""Tests for airodump station CSV parsing."""

from __future__ import annotations

from modules.monitor import parse_airodump_stations


SAMPLE_CSV = """\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2026-08-15 01:00:00, 2026-08-15 01:00:06, 6, 54, WPA2, CCMP, PSK, -40, 10, 0, 0.0.0.0, 5, LabAP,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-08-15 01:00:01, 2026-08-15 01:00:06, -45, 120, AA:BB:CC:DD:EE:FF,
77:88:99:AA:BB:CC, 2026-08-15 01:00:02, 2026-08-15 01:00:05, -60, 40, AA:BB:CC:DD:EE:FF, Guest
DE:AD:BE:EF:00:01, 2026-08-15 01:00:03, 2026-08-15 01:00:04, -70, 5, (not associated), OtherSSID
"""


def test_parse_airodump_stations_filters_by_bssid():
    stations = parse_airodump_stations(SAMPLE_CSV, "aa:bb:cc:dd:ee:ff")
    assert [s["mac"] for s in stations] == [
        "11:22:33:44:55:66",
        "77:88:99:AA:BB:CC",
    ]
    assert stations[0]["packets"] == "120"
    assert stations[1]["probes"] == "Guest"


def test_parse_airodump_stations_empty_when_no_match():
    assert parse_airodump_stations(SAMPLE_CSV, "00:11:22:33:44:55") == []


def test_parse_airodump_stations_empty_input():
    assert parse_airodump_stations("", "AA:BB:CC:DD:EE:FF") == []
