# Figo

figo— A terminal-based Wi-Fi security testing toolkit for authorized lab environments.

Use only on networks you own or have explicit written permission to test.

## Project layout

```text
figo/
├── figo                 # launcher
├── figo.py              # thin entrypoint
├── install.sh
├── README.md
├── ARCHITECTURE.md      # living architecture map
├── requirements.txt
├── modules/             # application modules (split from the old monolith)
│   ├── cli.py
│   ├── config.py
│   ├── capture.py
│   ├── cracking.py
│   ├── menu.py
│   ├── monitor.py
│   ├── network.py
│   ├── preflight.py
│   ├── setup_actions.py
│   ├── tools.py
│   ├── ui.py
│   ├── wordlists.py
│   └── figolab/                 # Evil Twin Lab + awareness portal
│       ├── evil_twin_menu.py    # Evil Twin submenu (setup + run actions)
│       ├── lab_config.py        # LabConfig / PortalConfig models + validation
│       ├── lab_session.py       # start / dashboard / cleanup orchestration
│       ├── ap_configs.py        # hostapd + dnsmasq config builders, lease parsing
│       ├── wireless_interface.py# interface snapshot / AP-mode prep / restore
│       ├── process_tracker.py   # child-process lifecycle tracking
│       └── awareness/
│           ├── portal_server.py     # captive-portal HTTP server (ports 80 + configured)
│           ├── portal_pages.py      # sign-in / connected / report HTML
│           ├── client_sessions.py   # per-client session store
│           └── awareness_metrics.py # non-sensitive behavioral metrics
```

Root keeps the normal user-facing files. All library code lives under `modules/`.

Internal structure, data flows, safety rules, and module map: see [`ARCHITECTURE.md`](ARCHITECTURE.md). Update that file whenever the project changes.

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

Menu **8** opens (Setup/Requirements first, then Run):

Setup / Requirements:

1. Configure awareness portal  
2. Configure lab network (gateway / DHCP / prefix / port / SSID / security)  
3. Adapter / preflight check  

Run:

4. Dry-run lab setup (show configs, no AP)  
5. **Security Awareness Lab** — controlled lab AP + local sign-in portal  
6. Preview portal page (current settings)  
0. Back  

Lab network choices:

- **Default:** `10.66.66.1` with DHCP `10.66.66.10`–`10.66.66.100` (recommended)
- **Home-style:** `192.168.1.1` with DHCP `192.168.1.10`–`192.168.1.100` (may conflict with real routers)
- **Customize:** gateway, DHCP range, subnet prefix, portal port, optional lab SSID (training variant)
- **AP security:** **open** (default) or **WPA2** with a lab passphrase you set and share with participants. WPA2 shows a padlock and removes the client "insecure / open network" warning, making the assessment more credible. The passphrase is the lab AP's own key — it is never a harvested credential.

Saved under `lab_network` in `~/.config/figo/config.json`. When starting a lab, Figo asks to confirm or change the addressing before launch, then runs a preflight check.

**Captive portal (auto pop-up):** the awareness portal listens on port **80** (where phones/laptops send captive-portal probes) in addition to the configured `portal_port`, and answers every request with the portal page. This makes the sign-in page appear automatically on connected devices instead of requiring the user to open a browser. dnsmasq resolves all DNS to the lab gateway to support this.

**Realistic (blind) scenario:** the client-facing pages are a classic Wi-Fi password form, then an ordinary "You are connected" confirmation.

The live Awareness dashboard shows behaviour events (clients, portal opens, sign-in submissions, **passwords entered**, completions) without ever storing passwords. This dashboard is the source of the screenshots for the manual report.

Hashcat GPU: **warning only**. Figo never installs GPU drivers; CPU (`aircrack-ng`) is the default crack engine.

Workflow (Security Awareness Lab):

1. Select wireless interface (or reuse the one already set)  
2. Discover nearby networks (reuses Figo scanning)  
3. Select an **authorized** target  
4. Review target SSID / BSSID / channel / band / security / signal / interface  
5. Confirm portal + network settings (incl. AP security)  
6. Explicit **Y/N** authorization confirmation (never auto-starts)  
7. Start controlled lab AP + local portal — Figo first hardens the adapter (rfkill unblock, unmanage from NetworkManager, stop any `wpa_supplicant` holding *this* interface) and fails fast with a clear message if the adapter lacks AP mode  
8. Participants connect → neutral sign-in page pops up → they submit → they see a normal "connected" page  
9. Live Rich dashboard captures their behaviour in real time and shows **service health (AP / DHCP-DNS / Portal)** and the **connected client list (IP · MAC · host)** — this is what you screenshot for the report. The portal auto-restarts if its HTTP server dies.  
10. Press **S** or **Ctrl+C** to stop  
11. Full cleanup and best-effort restore of the original interface / NetworkManager state  
12. Figo offers to **save a session report** (JSON + text, no secrets) under `~/figo-reports/` for the debrief  

### Reliability & troubleshooting

- If the AP fails to start, Figo shows the tail of the actual `hostapd` output (e.g. unsupported channel, driver refuses AP mode). It confirms the AP via hostapd's `AP-ENABLED` event rather than assuming success.
- If DHCP/DNS fails, the tail of `dnsmasq` output is shown (commonly port 53 taken by `systemd-resolved`).
- The lab AP defaults to open; use WPA2 (menu 3) to avoid the "insecure network" warning.

## Security Awareness Lab

The portal demonstrates why connecting to an unexpected duplicate Wi-Fi network is dangerous.

It measures **behavior**, not credentials.

### What is collected

Non-sensitive metrics only, for example:

- connected device count (DHCP leases)
- portal visits
- sign-in page views and form submissions
- whether a password field was left non-empty (a **boolean only** — never the value)
- security prompt interactions
- training completion flags
- temporary random session IDs (expire automatically)

### What is NOT collected

- real passwords
- password hashes retained as secrets
- cookies / tokens / browser credentials
- credential forwarding or exfiltration
- external telemetry services

### Sign-in simulation (password field)

To realistically measure behaviour, the portal shows a **classic password-only sign-in page** (enable/disable via *Configure awareness portal → Show a sign-in page*). This simulates an employee logging in on an unexpected Wi-Fi page. When the form is submitted:

1. The server reads the password field **only** to compute a single boolean (was it non-empty?), then **immediately discards** the value. It is never stored, logged, hashed, or transmitted.
2. The participant is shown an ordinary **"You are connected"** confirmation. The page does **not** reveal that this was a simulation — the reveal is intentionally deferred to the debrief / manual report so employees cannot detect the test from the page itself.
3. The tool's live dashboard updates with the behaviour in real time (opened the page, submitted the form, typed a password). This is the operator's evidence for the report.

If the sign-in page is disabled, the portal falls back to an explicit behavioural prompt (**“I would enter my password here”**) that never renders a password field. An optional admin-defined **fake training value** may also be configured; submitted input is compared in memory and **never written to logs or disk**.

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

Lab addressing is stored under `lab_network`:

- preset (`default` / `home` / `custom`)
- gateway_ip
- dhcp_range_start
- dhcp_range_end
- subnet_prefix
- portal_port
- ap_ssid (optional training SSID; empty = use target SSID)
- ap_security (`open` or `wpa2`)
- ap_passphrase (lab AP WPA2 key when `ap_security = wpa2`)

Portal sign-in options under `portal`:

- require_login (show the sign-in page with a password field)
- login_password_label / login_button_label

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

**Portal not reachable / does not pop up**  
Clients must join the lab SSID. The portal binds to the lab gateway IP on port **80** (captive-portal detection) plus the configured `portal_port` (default `8080`). DNS is redirected locally via dnsmasq so OS captive-portal probes reach the portal and the sign-in page opens automatically. If port 80 is already in use on the host, the portal still serves on `portal_port` but the automatic pop-up may not trigger — free port 80 or open `http://<gateway-ip>/` manually.

**Network shows as "insecure / open"**  
Open APs always warn on clients. Set **AP security → WPA2** in *Configure lab network* and share the lab passphrase with participants to show a padlock and remove the warning.

**Ctrl+C did not restore Wi-Fi**  
Re-run cleanup by starting/stopping the lab again, or manually: `nmcli device set <iface> managed yes` and reconnect.

## Safety boundary

Figo must not be extended into credential harvesting, phishing credential theft, cookie/session theft, stealth persistence, or external credential exfiltration. The Security Awareness Portal exists to teach and measure behavior without collecting real credentials.
