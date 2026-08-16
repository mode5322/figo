# Figo — Architecture

**Last updated:** 2026-08-16  
**Repo:** https://github.com/mode5322/Figo  
**Branch reviewed:** `cursor/cleanup-unused-portal-code-e15f`  
**Python LOC (app + tests):** ~4800+

This file is the source of truth for how Figo is structured. Update it in the same change whenever code, menus, config, safety rules, or layout change.

---

## 1. What Figo is (current status)

Figo is a **terminal-based Wi-Fi security testing toolkit** for **authorized lab environments**.

It is **not** a GUI app, **not** a background daemon, and **not** a network-wide C2/phishing platform.

Current product surface:

| Capability | Status | Notes |
|---|---|---|
| Adapter selection | Working | Shows capability probe (monitor/AP/managed) after pick |
| Network discovery + target pick | Working | `nmcli` preferred, `iw scan` fallback |
| Wordlist selection | Working | Common Kali paths + manual path |
| Tool check / apt install | Working | Tool packages only — **never NVIDIA/GPU drivers** |
| Preflight checks | Working | `modules/preflight.py` for capture + lab |
| Handshake capture (WPA/WPA2) | Working | Monitor + injection + deauth + airodump |
| WPA3 handling | Careful | Pure SAE blocked with guidance; mixed WPA2/WPA3 asks confirm |
| Offline crack (CPU) | Working | `aircrack-ng` (default engine) |
| Offline crack (GPU) | Optional | `hashcat` if backend already works; **warning only — no driver install** |
| Security Awareness Lab | Implemented | Lab AP (`hostapd`+`dnsmasq`, open **or WPA2**) + captive portal + sign-in simulation + live behaviour log; **no real password collection** |
| Blind (no on-screen reveal) | Working | Client sees a neutral sign-in then an ordinary "connected" page; the reveal is deferred to the debrief/manual report |
| Captive portal auto pop-up | Working | Portal binds port 80 + `portal_port`; catch-all serves sign-in so OS captive assistant opens |
| Sign-in simulation | Working | Classic password-only page; value discarded on submit, only a boolean behaviour recorded |
| Start-up hardening | Working | rfkill unblock, NM unmanage, stop `wpa_supplicant` on this iface, fail-fast AP-mode check |
| Robust service startup | Working | hostapd/dnsmasq output captured; wait for `AP-ENABLED`; log tail shown on failure |
| Live health + self-heal | Working | Dashboard shows AP/DHCP-DNS/Portal status + client list; portal auto-restarts on failure |
| Session report | Working | On stop, save JSON + text report (no secrets, no AP passphrase) to `~/figo-reports/` |
| Lab network options | Working | Gateway/DHCP presets, custom prefix/port/SSID, **AP security (open/WPA2)** |
| Dry-run lab setup | Working | Shows hostapd/dnsmasq configs without starting AP |
| Error handling in menus | Working | EOF/Ctrl+C, empty input, unexpected exceptions shown as panels |
| Hardware-in-the-loop tests | Not in CI | Unit tests mock subprocesses; no real Wi-Fi adapter in this environment |

**Safety boundary (must stay true):**

- No credential harvesting, forwarding, hashing-and-retaining of real passwords
- No cookie/token/browser-credential theft
- No external exfiltration
- Awareness portal measures **behavior**, not secrets
- The client-facing portal may run "blind" (no on-screen reveal) so it matches a real Evil Twin; this is a process choice for authorized assessments and does **not** change credential handling — submitted passwords are still discarded immediately and never stored. The reveal is delivered in an authorized debrief/report.
- Figo never installs proprietary GPU drivers

---

## 2. Runtime model

```text
User
  │
  ├─ ./figo                  (launcher, symlink target of /usr/local/bin/figo)
  │     runpy → figo.py
  │
  └─ python3 figo.py         (thin entry)
        │
        └─ modules.cli.main()
              │
              ├─ load ~/.config/figo/config.json
              ├─ optional --resume={capture|crack|install|evil_twin}  (sudo re-exec)
              └─ main menu loop (1–8)
```

`install.sh` only creates a **symlink** to the repo-local `figo` launcher. It does not copy Python files into `/usr/local`. The working tree must remain on disk.

Root escalation: privileged actions call `ensure_root(resume)` which `exec`s:

```text
sudo -E python figo.py --resume=<action>
```

Resume keys: `capture`, `crack`, `install`, `evil_twin`.

Config home under sudo: `effective_home()` prefers `/home/$SUDO_USER` so root sessions still read the operator’s `~/.config/figo`.

---

## 3. Repository layout

Root = user-facing files. All library code lives under `modules/`.

```text
Figo/
├── figo                      # launcher (runpy → figo.py)
├── figo.py                   # thin entry (sys.path + modules.cli.main)
├── install.sh                # symlink installer / uninstall
├── README.md                 # user docs
├── ARCHITECTURE.md           # this file
├── requirements.txt          # rich>=13
├── .gitignore
├── .cursor/rules/architecture.mdc
├── modules/                  # application package
│   ├── __init__.py
│   ├── cli.py                # main loop + dispatch
│   ├── menu.py               # main menu render
│   ├── ui.py                 # prompts, panels, run_action
│   ├── exceptions.py         # BackToMenu, ExitApp
│   ├── constants.py          # paths, bins, capture timings
│   ├── config.py             # Settings/Target JSON persistence
│   ├── network.py            # interfaces + scan
│   ├── wordlists.py
│   ├── tools.py              # which/missing/apt/root/require_*
│   ├── setup_actions.py      # menu 1–4
│   ├── monitor.py            # airmon/airodump/aireplay helpers
│   ├── capture.py            # menu 6
│   ├── cracking.py           # menu 7
│   └── figolab/                  # menu 8 Evil Twin + awareness
│       ├── evil_twin_menu.py     # lab submenu CLI (setup + run)
│       ├── lab_session.py        # start/dashboard/cleanup orchestration
│       ├── ap_configs.py         # hostapd/dnsmasq config builders + lease parsing
│       ├── wireless_interface.py # snapshot/restore NM + iface, AP-mode prep
│       ├── process_tracker.py    # tracked Popen children
│       ├── lab_config.py         # LabConfig / PortalConfig models + validation
│       └── awareness/
│           ├── portal_server.py     # ThreadingHTTPServer captive portal
│           ├── client_sessions.py   # per-client session store
│           ├── awareness_metrics.py # non-sensitive behavioral counters
│           └── portal_pages.py      # sign-in / connected / report HTML
```

---

## 4. Module map

### 4.1 Core CLI

| Module | Responsibility |
|---|---|
| `figo.py` | Insert repo root on `sys.path`; catch `KeyboardInterrupt`/`ExitApp` |
| `modules/cli.py` | Load settings; resume privileged action; menu loop; `run_action` dispatch |
| `modules/menu.py` | Rich main menu (options 1–8) |
| `modules/ui.py` | `ask`/`confirm`/`pause`/`warn_and_back`/`report_error`/`run_action`/`parse_menu_index` |
| `modules/exceptions.py` | `BackToMenu` (submenu cancel), `ExitApp` (leave program) |

### 4.2 State and helpers

| Module | Responsibility |
|---|---|
| `modules/constants.py` | `APP_NAME`, handshake dir, capture timings (`STATION_SCAN_SEC`), `TOOL_PACKAGES`, required/optional bins |
| `modules/config.py` | `Target`, `Settings`, load/save `~/.config/figo/config.json` |
| `modules/network.py` | Wireless iface list, `nmcli`/`iw` scan, safe signal sort |
| `modules/wordlists.py` | Discover wordlists under common dirs |
| `modules/tools.py` | Binary detection, apt install UI, `ensure_root`, readiness checks |
| `modules/preflight.py` | Adapter capability probe + preflight reports |
| `modules/setup_actions.py` | Adapter / target / wordlist / show settings |

### 4.3 Handshake audit

| Module | Responsibility |
|---|---|
| `modules/monitor.py` | Monitor mode via `airmon-ng`, airodump Popen, associated-station CSV scan, deauth, injection test |
| `modules/capture.py` | Pre-confirm client list + 90s capture loop with deauth bursts and handshake detection |
| `modules/cracking.py` | Pick `.cap`, aircrack-ng CPU or hashcat GPU (22000); GPU probe + alert panels |

### 4.4 Evil Twin Lab (`modules/figolab`)

| Module | Responsibility |
|---|---|
| `evil_twin_menu.py` | Submenu (Setup/Requirements then Run); run flow, live dashboard (health + client list), report save prompt |
| `lab_config.py` | `LabConfig`, `PortalConfig`, SSID/channel/passphrase validation, lab bins |
| `lab_session.py` | Harden + prepare iface, start hostapd/dnsmasq/portal with captured logs, `ensure_services()` self-heal, `build_session_report()`/`save_session_report()`, `cleanup_lab_session()` |
| `ap_configs.py` | Write hostapd (open **or WPA2-PSK**) + dnsmasq configs; `parse_dhcp_leases()` client records |
| `wireless_interface.py` | Snapshot operstate/mode/addrs/NM; restore after lab; `rfkill_unblock()`, `stop_interfering_processes()` |
| `process_tracker.py` | Track only Figo-started children; SIGTERM then kill |
| `awareness/portal_server.py` | Local HTTP portal; binds port 80 + `portal_port`; catch-all serves sign-in; `/login` discards password value, records boolean behaviour only |
| `awareness/client_sessions.py` | UUID-like `secrets.token_urlsafe` sessions with TTL |
| `awareness/awareness_metrics.py` | In-memory counters (incl. `login_submissions`, `passwords_entered`); refuse sensitive keys |
| `awareness/portal_pages.py` | HTML sign-in / connected / report pages (operator report lists recorded behaviours) |

---

## 5. Main menu (do not renumber blindly)

```text
Setup
  1  Select a network adapter
  2  Discover networks and select a test target
  3  Select a password wordlist file
  4  Show current settings
  5  Check / install tools
Run
  6  Capture handshake
  7  Crack a saved handshake
  8  Evil Twin Lab
Ctrl+C / EOF on this prompt → exit
Empty Enter → ignored (no “unknown option”)
```

Evil Twin submenu (8):

```text
  Setup / Requirements
  1  Configure awareness portal
  2  Configure lab network (gateway / DHCP / prefix / port / SSID / security)
  3  Adapter / preflight check
  ------------------------
  Run
  4  Dry-run lab setup (show configs, no AP)
  5  Security Awareness Lab (open/WPA2 AP + captive sign-in portal)
  0  Back
```

Setup/requirement options come first (mirroring the main menu), then the
executable options. The standalone "Wi-Fi Lab" (AP without a portal) was
removed: the lab now always runs the awareness scenario so it matches a real
Evil Twin end-to-end.

---

## 6. Configuration

**File:** `~/.config/figo/config.json`  
**Compatibility:** Old files without `portal` still load (`portal` defaults to `{}`).

```json
{
  "interface": "wlan0",
  "wordlist": "/usr/share/wordlists/rockyou.txt",
  "handshake_dir": "<repo>/handshakes",
  "target": {
    "ssid": "",
    "bssid": "",
    "channel": "",
    "signal": "",
    "security": ""
  },
  "portal": {
    "enabled": true,
    "organization": "",
    "portal_title": "SECURITY AWARENESS TEST",
    "training_message": "...",
    "security_contact": "",
    "educational_message": "",
    "training_value": "",
    "logo_path": "",
    "session_ttl_sec": 3600,
    "require_login": true,
    "login_username_label": "",
    "login_password_label": "Password",
    "login_button_label": "Connect"
  },
  "lab_network": {
    "preset": "default",
    "gateway_ip": "10.66.66.1",
    "dhcp_range_start": "10.66.66.10",
    "dhcp_range_end": "10.66.66.100",
    "subnet_prefix": "24",
    "portal_port": "8080",
    "ap_ssid": "",
    "ap_security": "open",
    "ap_passphrase": ""
  }
}
```

Save failures raise `OSError` and are shown to the user (not a silent crash).
`lab_network` is optional for backward compatibility; missing key defaults to `10.66.66.x`.
Empty `ap_ssid` means the lab AP uses the selected target SSID.

---

## 7. Feature flows

### 7.1 Handshake capture (menu 6)

Preconditions: adapter, target BSSID, valid channel; **WPA3/SAE is rejected**; root + aircrack-ng tools.

```text
enable monitor (airmon-ng start)
  → brief airodump CSV scan (STATION_SCAN_SEC=6) for associated clients
  → "Capture handshake" summary panel (network info + Connected devices list)
  → confirm Continue?
  → injection test (aireplay-ng -9)
  → airodump-ng --bssid -c -w pcap
  → warmup 4s
  → up to 8 deauth bursts (count=5) with 8s gaps
  → handshake check via cowpatty then aircrack-ng
  → timeout 90s
  → stop airodump + airmon stop + restart NetworkManager
```

The confirmation panel lists each associated station MAC / power / packets / probes (or “none seen” if the short scan found no clients). Cancel restores the adapter.

Captures land in `handshakes/` (gitignored).

### 7.2 Offline crack (menu 7)

```text
list .cap/.pcap in handshake_dir
  → pick file
  → parse networks in capture (aircrack-ng)
  → if hashcat present: choose 1=CPU / 2=GPU (default GPU)
  → GPU path:
       collect GPU info (lspci + nvidia-smi + `hashcat -I`)
       → show GPU information panel
       → if backend unusable: Warning panel includes GPU details + optional CPU fallback
       → hcxpcapngtool → .hc22000 → hashcat -m 22000 -D 2
       → on hashcat GPU/backend failure: Warning panel with GPU details + optional CPU fallback
  → CPU path: aircrack-ng -a2 -w wordlist
```

Figo **never** installs NVIDIA/CUDA/ROCm drivers. GPU cracking is host-dependent.
GPU alerts show PCI adapters, `nvidia-smi` rows when available, and hashcat backend device/error text.
### 7.3 Evil Twin / Awareness (menu 8)

Submenu:

```text
  Setup / Requirements
  1  Configure awareness portal (incl. sign-in page toggle)
  2  Configure lab network (gateway / DHCP / port / SSID / security)
  3  Adapter / preflight check
  ------------------------
  Run
  4  Dry-run lab setup
  5  Security Awareness Lab
  0  Back
```

Lab network presets (saved under `lab_network` in config.json):

| Choice | Gateway | DHCP | Notes |
|---|---|---|---|
| Default | `10.66.66.1` | `10.66.66.10`–`10.66.66.100` | Recommended |
| Home-style | `192.168.1.1` | `192.168.1.10`–`192.168.1.100` | May conflict with real routers |
| Customize | operator-defined | operator-defined | Also: subnet prefix, portal port, optional lab SSID |
| AP security | open / WPA2 | — | WPA2 uses an admin-set lab passphrase (padlock; removes "insecure" warning) |

```text
ensure root + hostapd/dnsmasq/iw/ip
  → scan (reuse modules.network.scan_networks)
  → pick authorized target
  → confirm / configure lab network (gateway + DHCP + port + SSID + security)
  → preflight (AP capability, DNS/portal ports, tools)
  → optional portal config
  → explicit Y/N confirmation (never auto-start)
  → snapshot iface
  → harden: rfkill unblock, unmanage NM, stop wpa_supplicant bound to THIS iface,
            fail fast if adapter cannot do AP mode
  → assign configured gateway/prefix
  → hostapd (open wpa=0, or WPA2-PSK) with output captured; wait for AP-ENABLED,
            surface hostapd log tail on failure
  → dnsmasq DHCP/DNS with output captured; surface log tail on failure
  → awareness HTTP on gateway:80 (captive) + gateway:portal_port (mode=awareness)
  → live Rich dashboard: service health (AP/DHCP-DNS/Portal), connected client
            list (ip/mac/host), behaviour log; portal auto-restarts if it dies;
            S or Ctrl+C
  → build_session_report() BEFORE cleanup (metrics/leases still present)
  → cleanup_lab_session()  (idempotent; closes captured log handles)
  → offer to save report (JSON + text, no secrets) under ~/figo-reports/
```

Dry-run (submenu 4) builds and displays hostapd/dnsmasq configs without starting processes or changing interfaces.

Live dashboard events (non-sensitive): client connect/leave, portal open, sign-in view, sign-in submission, **password entered (boolean only)**, training, completion.

**Captive portal:** the portal binds port 80 (OS captive-portal probes) plus `portal_port`, and its catch-all handler answers every request with the sign-in page, so the assistant opens automatically on clients. dnsmasq points all DNS at the gateway.

**Sign-in simulation (blind):** when `portal.require_login` is true (default), the landing page is a classic password-only form posting to `/login`. The handler reads the password field only to compute `entered_password` (a boolean) and discards the value immediately. The client is then shown `templates.connected_page`. Dead templates (`training_page`, `result_page`) were removed.

**AP security:** the lab AP defaults to open (`wpa=0`) but can be WPA2-PSK using an admin-set lab passphrase (the AP's own key, shared with participants — never a harvested credential) to avoid the client "insecure network" warning.

`192.168.1.1` may conflict with real home routers; `10.66.66.1` remains the recommended default.

### 7.4 Hashcat GPU policy

- Default crack engine is **aircrack-ng (CPU)**.
- Hashcat GPU is optional and only runs if `hashcat -I` already shows a usable backend.
- Figo **never** installs NVIDIA/AMD/CUDA/OpenCL drivers (menu 5 installs tool packages like `hashcat` only).
- On GPU failure, Figo shows a warning panel and offers CPU fallback.

Cleanup:

1. Stop portal  
2. Terminate tracked hostapd/dnsmasq only  
3. Clear sessions/metrics  
4. Delete tempfile dir (`figo-lab-*`)  
5. Restore iface mode/addresses and NM managed/connection  

Runs on success stop, Ctrl+C, `S`, and startup failure (`try/finally`).

---

## 8. Error handling

| Event | Behavior |
|---|---|
| Ctrl+C / EOF in submenu prompt | `BackToMenu` → return to menu |
| Ctrl+C / EOF on main “Choose a number” | `ExitApp` → goodbye |
| Empty main-menu Enter | Loop again, no warning |
| Invalid menu number | Warning panel, then back |
| Unexpected exception in an action | `run_action` → Error panel, stay in Figo |
| Unexpected exception in menu loop | `report_error`, continue loop |
| Scan `signal` non-numeric | Sort key 0 (no crash) |
| Missing lab bins | Warning; **no silent apt install** from Evil Twin |
| Lab AP/DHCP fail | `LabError` with actionable causes |
| hashcat GPU backend missing / init fail | Warning panel includes PCI + hashcat backend GPU info; optional CPU fallback |
| hashcat run GPU error | Same GPU detail block in Warning panel; optional CPU fallback |

---

## 9. External tools

**Required for capture:** `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`  
**Optional:** `cowpatty`, `iw`, `nmcli`, `hashcat`, `hcxpcapngtool`, `hostapd`, `dnsmasq`, `ip`  
**Lab required:** `hostapd`, `dnsmasq`, `iw`, `ip`

Python dependency: `rich>=13.0.0`.

---

## 10. Verification

The automated `tests/` suite was removed at the maintainer's request. Verify
changes with import + smoke checks instead:

```bash
# import graph must load cleanly
python3 -c "import figo, modules.cli, modules.figolab.evil_twin_menu, modules.figolab.lab_session"

# core flows: config builders, portal pages, metrics (no hardware needed)
python3 -c "from modules.figolab.ap_configs import build_hostapd_conf; \
from modules.figolab.awareness import portal_pages; print('ok')"
```

No physical Wi-Fi hardware is required for import/smoke checks. Do not claim
over-the-air AP/capture was tested unless hardware was actually used.

---

## 11. Known limitations / debt

1. `render_banner()` is a no-op.
2. Lab AP supports open (`wpa=0`) or WPA2-PSK (`wpa=2`) with a shared passphrase; it does not clone the exact PSK of the target.
3. Portal `logo_path` is stored but not rendered in HTML yet.
4. Pure WPA3/SAE capture remains unsupported (by design); mixed WPA2/WPA3 can continue with an explicit caution.
5. Hashcat GPU depends on a host backend that the operator already installed; Figo only warns and falls back to CPU.
6. Real AP-mode / monitor-mode behavior is hardware-specific (USB nl80211 recommended).
7. `install.sh` does not `chmod` Python modules under `modules/` (not required; they are imported, not executed as scripts).
8. Capability probe uses `iw` parsing and may report unknown (`?`) on unusual drivers.

---

## 12. Maintenance rule

When changing **any** of: layout, menus, config schema, capture/crack/lab flows, safety, dependencies, tests:

1. Edit `ARCHITECTURE.md` in the same commit.
2. Refresh “Last updated” and the reviewed commit hash.
3. Keep this file factual — no planned features listed as implemented.

Cursor rule: `.cursor/rules/architecture.mdc` (always apply).
