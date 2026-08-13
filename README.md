# Figo

figo— A terminal-based Wi-Fi security testing toolkit for authorized lab environments.

Use only on networks you own or have explicit written permission to test.

## Install

```bash
git clone https://github.com/mode5322/figo.git
cd figo
python3 -m pip install -r requirements.txt
chmod +x install.sh figo figo.py
sudo ./install.sh
```

This puts a symlink in `/usr/local/bin/figo`, so the command works from any directory **as a normal user and as root**.

```bash
figo
```

### User-only install (not recommended)

```bash
./install.sh --user
```

### Uninstall

```bash
sudo ./install.sh --uninstall
```

### Without installing

```bash
./figo
# or
python3 figo.py
```

## Requirements

Python 3 with `rich`.

Core Wi-Fi audit tools (Kali/Debian):

```bash
sudo apt install python3-rich aircrack-ng cowpatty iw
```

Evil Twin Lab extras:

```bash
sudo apt install hostapd dnsmasq iproute2 iw network-manager
```

Hardware notes:

- A wireless adapter that supports **AP mode** is required for Evil Twin Lab.
- Many built-in laptop cards do not support AP mode reliably.
- USB adapters with `nl80211` AP support work best.
- Real over-the-air Evil Twin behavior was not assumed tested in CI.

Inside the app, menu **5 — Check / install tools** can install missing packages when you confirm.

## Main menu

1. Select a network adapter  
2. Discover networks and select a test target  
3. Select a password wordlist file  
4. Show current settings  
5. Check / install tools  
6. Capture handshake  
7. Crack a saved handshake  
8. Evil Twin Lab  

## Evil Twin Lab

Menu **8** opens:

1. **Wi-Fi Lab** — controlled open lab AP (no awareness portal)  
2. **Security Awareness Lab** — controlled lab AP + local awareness portal  
3. Configure awareness portal  
0. Back  

Workflow (Security Awareness Lab):

1. Select wireless interface (or reuse the one already set)  
2. Discover nearby networks (reuses Figo scanning)  
3. Select an **authorized** target  
4. Review target SSID / BSSID / channel / band / security / signal / interface  
5. Confirm portal settings  
6. Explicit **Y/N** authorization confirmation (never auto-starts)  
7. Start controlled lab AP + local portal  
8. Live Rich dashboard with connected devices / visits / interactions  
9. Press **S** or **Ctrl+C** to stop  
10. Full cleanup and best-effort restore of the original interface / NetworkManager state  

## Security Awareness Lab

The portal demonstrates why connecting to an unexpected duplicate Wi-Fi network is dangerous.

It measures **behavior**, not credentials.

### What is collected

Non-sensitive metrics only, for example:

- connected device count (DHCP leases)
- portal visits
- security prompt interactions
- training completion flags
- temporary random session IDs (expire automatically)

### What is NOT collected

- real passwords
- password hashes retained as secrets
- cookies / tokens / browser credentials
- credential forwarding or exfiltration
- external telemetry services

The portal UI uses behavioral actions such as **“I would enter my password here”**.  
It does **not** ask for a real password. An optional admin-defined **fake training value** may be configured; submitted input is compared in memory and **never written to logs or disk**.

## Authorized Use

This toolkit is for:

- authorized security assessments
- controlled laboratory environments
- security awareness training with permission

Unauthorized use against networks you do not own or lack permission to test is illegal.

## Configuration

Figo stores settings in:

`~/.config/figo/config.json`

Existing fields remain backward compatible. Portal settings are stored under the `portal` key:

- enabled
- organization name
- portal title
- training message
- security contact
- educational message
- optional fake training value
- optional logo path

## Cleanup

Evil Twin Lab uses one central cleanup path:

- stop awareness portal
- stop dnsmasq / hostapd and tracked child processes only
- delete temporary config / lease / session files under a tempfile directory
- restore wireless interface mode/addresses when possible
- restore NetworkManager managed state when it was changed

Cleanup runs on normal stop, **S**, Ctrl+C, and startup failures. Calling cleanup twice is safe.

## Troubleshooting

**`[ERROR] Required dependency not found: hostapd`**  
Install `hostapd` (and usually `dnsmasq`) via menu 5 or apt. Figo does not silently install from the Evil Twin menu.

**Failed to start the lab AP**  
Possible causes:

- adapter does not support AP mode
- invalid hostapd configuration / unsupported channel
- another process is using the interface
- NetworkManager still managing the interface

**Portal not reachable**  
Clients must join the lab SSID. Portal binds to the lab gateway IP (default `10.66.66.1:8080`). DNS is redirected locally via dnsmasq for captive-portal style discovery.

**Ctrl+C did not restore Wi-Fi**  
Re-run cleanup by starting/stopping the lab again, or manually: `nmcli device set <iface> managed yes` and reconnect.

## Tests

```bash
python3 -m pip install -r requirements.txt pytest
python3 -m pytest
```

Tests mock subprocess/network operations and do not require Wi-Fi hardware.

## Safety boundary

Figo must not be extended into credential harvesting, phishing credential theft, cookie/session theft, stealth persistence, or external credential exfiltration. The Security Awareness Portal exists to teach and measure behavior without collecting real credentials.
