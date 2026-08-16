# Figo

Terminal Wi-Fi security toolkit for **authorized lab environments**.

Use only on networks you own or have explicit written permission to test.

For internal code structure, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Install

```bash
git clone https://github.com/mode5322/figo.git
cd figo
python3 -m pip install -r requirements.txt
chmod +x install.sh figo figo.py
sudo ./install.sh
```

Then run from anywhere:

```bash
figo
```

| Option | Command |
|---|---|
| User-only install (not recommended) | `./install.sh --user` |
| Uninstall | `sudo ./install.sh --uninstall` |
| Run without installing | `./figo` or `python3 figo.py` |

---

## Requirements

- Python 3 with `rich`
- Wireless adapter that supports **monitor mode** (handshake) and/or **AP mode** (Evil Twin Lab)
- USB adapters with `nl80211` AP support work best; many built-in laptop cards do not

Core tools (Kali/Debian):

```bash
sudo apt install python3-rich aircrack-ng cowpatty iw
```

Evil Twin Lab extras:

```bash
sudo apt install hostapd dnsmasq iproute2 iw network-manager
```

Inside the app, menu **5 — Check / install tools** can install missing packages when you confirm. Figo never installs GPU/NVIDIA drivers.

---

## Main menu

### Setup

| # | Option | What it does |
|---|---|---|
| **1** | Select a network adapter | Pick the wireless interface Figo will use |
| **2** | Discover networks and select a test target | Scan nearby Wi-Fi and choose an **authorized** target |
| **3** | Select a password wordlist file | Choose a wordlist for handshake cracking |
| **4** | Show current settings | Display adapter, target, wordlist, and saved options |
| **5** | Check / install tools | Detect missing packages and optionally install them |

### Run

| # | Option | What it does |
|---|---|---|
| **6** | Capture handshake | Capture a WPA/WPA2 handshake from the selected target |
| **7** | Crack a saved handshake | Crack a saved `.cap` with aircrack-ng (CPU) or hashcat (GPU if already working) |
| **8** | Evil Twin Lab | Controlled lab AP + security awareness portal |

Empty Enter on the main menu is ignored. Ctrl+C / EOF exits.

---

## Evil Twin Lab (menu 8)

Setup options first, then run options.

### Setup / Requirements

| # | Option | What it does |
|---|---|---|
| **1** | Configure awareness portal | Set organization name, page titles, messages, whether to show a sign-in form, and field labels |
| **2** | Configure lab network | Set gateway / DHCP / subnet / portal port / lab SSID, and AP security (**open** or **WPA2**) |
| **3** | Adapter / preflight check | Verify the adapter and tools are ready (AP mode, required binaries) before a live run |

### Run

| # | Option | What it does |
|---|---|---|
| **4** | Dry-run lab setup | Show the generated hostapd/dnsmasq configs **without** starting an AP |
| **5** | Security Awareness Lab | Start the lab AP + captive sign-in portal and open the live dashboard |
| **0** | Back | Return to the main menu |

### Lab network choices (option 2)

- **Default:** `10.66.66.1`, DHCP `10.66.66.10`–`10.66.66.100` (recommended)
- **Home-style:** `192.168.1.1`, DHCP `192.168.1.10`–`192.168.1.100` (may conflict with real routers)
- **Customize:** your own gateway, DHCP range, prefix, portal port, optional lab SSID
- **AP security:** **open** or **WPA2** with a lab passphrase you share with participants  
  WPA2 shows a padlock and removes the client “insecure / open network” warning. That passphrase is the lab AP’s own key — never a harvested credential.

Settings are saved in `~/.config/figo/config.json`.

### How the awareness scenario works

1. Clients join the lab SSID.
2. The sign-in page pops up automatically (portal listens on port **80** + your configured portal port; DNS is redirected to the lab gateway).
3. The page looks like a normal Wi-Fi login. After submit, the client sees an ordinary **“You are connected”** page — it does **not** say this is a test.
4. Your live dashboard records behaviour only (see below). Use screenshots + the session report for the later debrief.
5. Press **S** or **Ctrl+C** to stop. Figo cleans up and can save a report under `~/figo-reports/`.

### Security Awareness Lab workflow (option 5)

1. Select wireless interface (or reuse the one already set)
2. Discover nearby networks
3. Select an **authorized** target
4. Review target SSID / BSSID / channel / band / security / signal / interface
5. Confirm portal + network settings (including AP security)
6. Explicit **Y/N** authorization confirmation (never auto-starts)
7. Figo hardens the adapter, then starts the lab AP + portal
8. Participants connect → sign-in page → “connected” page
9. Live dashboard shows behaviour, **service health** (AP / DHCP-DNS / Portal), and **connected clients** (IP · MAC · host)
10. Stop with **S** or **Ctrl+C**
11. Cleanup restores the interface / NetworkManager state when possible
12. Optional: save a session report (JSON + text, no secrets)

---

## What is measured (and what is not)

### Collected (behaviour only)

- Connected device count (DHCP leases)
- Portal visits and sign-in page views / submissions
- Whether a password field was non-empty (**boolean only** — never the value)
- Security-prompt interactions and training completion flags
- Temporary random session IDs (expire automatically)

### Never collected

- Real passwords or password hashes kept as secrets
- Cookies / tokens / browser credentials
- Credential forwarding or exfiltration
- External telemetry

When the sign-in form is submitted, the password is read only to decide “empty or not?”, then **discarded immediately**. It is never stored, logged, hashed, or transmitted.

If the sign-in page is disabled in portal settings, the portal falls back to an explicit behavioural prompt that never shows a password field.

---

## Configuration file

Path: `~/.config/figo/config.json`

**Portal** (`portal`):

- organization, titles, training / educational messages, security contact
- optional logo path and optional fake training value
- `require_login` and login field labels

**Lab network** (`lab_network`):

- preset (`default` / `home` / `custom`)
- gateway, DHCP range, subnet prefix, portal port
- optional lab SSID (`ap_ssid`; empty = use target SSID)
- `ap_security` (`open` or `wpa2`) and `ap_passphrase` when WPA2 is used

Old config files without these keys still load with safe defaults.

---

## Cleanup

On stop, **S**, Ctrl+C, or startup failure, Figo:

- stops the portal, dnsmasq, and hostapd (only processes it started)
- deletes temporary lab files
- restores the wireless interface and NetworkManager managed state when possible

Cleanup is safe to run more than once.

---

## Troubleshooting

**`Required dependency not found: hostapd`**  
Install `hostapd` (and usually `dnsmasq`) via menu **5** or apt.

**Failed to start the lab AP**  
Adapter may lack AP mode, channel may be unsupported, another process may hold the interface, or NetworkManager may still manage it. Figo prints the `hostapd` log tail on failure.

**Portal does not pop up**  
Clients must join the lab SSID. Port **80** must be free for automatic captive-portal detection. If 80 is busy, open `http://<gateway-ip>/` (or the configured portal port) manually.

**Network shows as “insecure / open”**  
Set **AP security → WPA2** in Evil Twin option **2** and share the lab passphrase with participants.

**DHCP / DNS failed**  
Often port 53 is taken (e.g. by `systemd-resolved`). Figo shows the `dnsmasq` log tail.

**Ctrl+C did not restore Wi-Fi**  
Start/stop the lab again, or run:  
`nmcli device set <iface> managed yes` then reconnect.

---

## Authorized use only

Figo is for authorized assessments, controlled labs, and security awareness training with permission.

Unauthorized use against networks you do not own or lack permission to test is illegal.

Figo must not be extended into credential harvesting, phishing credential theft, cookie/session theft, stealth persistence, or external credential exfiltration. The awareness portal measures **behaviour**, not secrets.
