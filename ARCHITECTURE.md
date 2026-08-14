# Figo — Architecture

**Last updated:** 2026-08-14  
**Repo:** https://github.com/mode5322/Figo  
**Branch reviewed:** `main` (`20b4c87`)  
**Python LOC (app + tests):** ~3800

This file is the source of truth for how Figo is structured. Update it in the same change whenever code, menus, config, safety rules, or layout change.

---

## 1. What Figo is (current status)

Figo is a **terminal-based Wi-Fi security testing toolkit** for **authorized lab environments**.

It is **not** a GUI app, **not** a background daemon, and **not** a network-wide C2/phishing platform.

Current product surface:

| Capability | Status | Notes |
|---|---|---|
| Adapter selection | Working | `/sys/class/net` then `iw dev` |
| Network discovery + target pick | Working | `nmcli` preferred, `iw scan` fallback |
| Wordlist selection | Working | Common Kali paths + manual path |
| Tool check / apt install | Working | Requires root; not silent from Evil Twin menu |
| Handshake capture (WPA/WPA2) | Working | Monitor + injection + deauth + airodump |
| Offline crack (CPU) | Working | `aircrack-ng` |
| Offline crack (GPU) | Optional | `hashcat` + `hcxpcapngtool`; **can break the host if NVIDIA drivers are installed incorrectly** — Figo does not install GPU drivers |
| Evil Twin Wi-Fi Lab | Implemented | Open lab AP via `hostapd` + `dnsmasq` |
| Security Awareness Lab | Implemented | Same AP + local HTTP portal; **no real password collection** |
| Error handling in menus | Working | EOF/Ctrl+C, empty input, unexpected exceptions shown as panels |
| Hardware-in-the-loop tests | Not in CI | Unit tests mock subprocesses; no real Wi-Fi adapter in this environment |

**Safety boundary (must stay true):**

- No credential harvesting, forwarding, hashing-and-retaining of real passwords
- No cookie/token/browser-credential theft
- No external exfiltration
- Awareness portal measures **behavior**, not secrets

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
├── pytest.ini
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
│   └── figolab/              # menu 8 Evil Twin + awareness
│       ├── evil_twin.py      # lab CLI
│       ├── lab_session.py    # start/cleanup orchestration
│       ├── ap.py             # hostapd/dnsmasq config builders
│       ├── interface.py      # snapshot/restore NM + iface
│       ├── processes.py      # tracked Popen children
│       ├── models.py         # LabConfig / PortalConfig
│       └── awareness/
│           ├── portal.py     # ThreadingHTTPServer
│           ├── session.py
│           ├── metrics.py
│           └── templates.py
└── tests/
    ├── test_figolab.py
    └── test_ui_errors.py
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
| `modules/constants.py` | `APP_NAME`, handshake dir, capture timings, `TOOL_PACKAGES`, required/optional bins |
| `modules/config.py` | `Target`, `Settings`, load/save `~/.config/figo/config.json` |
| `modules/network.py` | Wireless iface list, `nmcli`/`iw` scan, safe signal sort |
| `modules/wordlists.py` | Discover wordlists under common dirs |
| `modules/tools.py` | Binary detection, apt install UI, `ensure_root`, readiness checks |
| `modules/setup_actions.py` | Adapter / target / wordlist / show settings |

### 4.3 Handshake audit

| Module | Responsibility |
|---|---|
| `modules/monitor.py` | Monitor mode via `airmon-ng`, airodump Popen, deauth, injection test |
| `modules/capture.py` | 90s capture loop with deauth bursts and handshake detection |
| `modules/cracking.py` | Pick `.cap`, aircrack-ng CPU or hashcat GPU (22000) |

### 4.4 Evil Twin Lab (`modules/figolab`)

| Module | Responsibility |
|---|---|
| `evil_twin.py` | Submenu: Wi-Fi Lab / Awareness Lab / portal config |
| `models.py` | `LabConfig`, `PortalConfig`, SSID/channel validation, lab bins |
| `lab_session.py` | Prepare iface, start hostapd/dnsmasq/portal, `cleanup_lab_session()` |
| `ap.py` | Write **open** hostapd + dnsmasq configs into tempfile dir |
| `interface.py` | Snapshot operstate/mode/addrs/NM; restore after lab |
| `processes.py` | Track only Figo-started children; SIGTERM then kill |
| `awareness/portal.py` | Local HTTP awareness pages; no password field |
| `awareness/session.py` | UUID-like `secrets.token_urlsafe` sessions with TTL |
| `awareness/metrics.py` | In-memory counters; refuse sensitive keys |
| `awareness/templates.py` | HTML landing/result pages |

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
  1  Wi-Fi Lab              (open AP, no portal)
  2  Security Awareness Lab (open AP + portal)
  3  Configure awareness portal
  0  Back
```

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
    "educational_message": "...",
    "training_value": "",
    "logo_path": "",
    "session_ttl_sec": 3600
  }
}
```

Save failures raise `OSError` and are shown to the user (not a silent crash).

---

## 7. Feature flows

### 7.1 Handshake capture (menu 6)

Preconditions: adapter, target BSSID, valid channel; **WPA3/SAE is rejected**; root + aircrack-ng tools.

```text
enable monitor (airmon-ng start)
  → injection test (aireplay-ng -9)
  → airodump-ng --bssid -c -w pcap
  → warmup 4s
  → up to 8 deauth bursts (count=5) with 8s gaps
  → handshake check via cowpatty then aircrack-ng
  → timeout 90s
  → stop airodump + airmon stop + restart NetworkManager
```

Captures land in `handshakes/` (gitignored).

### 7.2 Offline crack (menu 7)

```text
list .cap/.pcap in handshake_dir
  → pick file
  → parse networks in capture (aircrack-ng)
  → if hashcat present: choose 1=CPU / 2=GPU (default GPU)
  → GPU path: hcxpcapngtool → .hc22000 → hashcat -m 22000
  → CPU path: aircrack-ng -a2 -w wordlist
```

Figo **never** installs NVIDIA/CUDA/ROCm drivers. GPU cracking is host-dependent.

### 7.3 Evil Twin / Awareness (menu 8)

```text
ensure root + hostapd/dnsmasq/iw/ip
  → scan (reuse modules.network.scan_networks)
  → pick authorized target
  → optional portal config
  → explicit Y/N confirmation (never auto-start)
  → snapshot iface + unmanage NM
  → assign 10.66.66.1/24
  → hostapd (open AP, wpa=0) + dnsmasq DHCP/DNS
  → awareness HTTP on gateway:8080 (mode=awareness)
  → live Rich dashboard; S or Ctrl+C
  → cleanup_lab_session()  (idempotent)
```

Lab AP is **intentionally open**. Awareness happens in the portal, not via a fake WPA password.

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

---

## 9. External tools

**Required for capture:** `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`  
**Optional:** `cowpatty`, `iw`, `nmcli`, `hashcat`, `hcxpcapngtool`, `hostapd`, `dnsmasq`, `ip`  
**Lab required:** `hostapd`, `dnsmasq`, `iw`, `ip`

Python dependency: `rich>=13.0.0`.

---

## 10. Tests

```bash
python3 -m pytest
```

| File | Covers |
|---|---|
| `tests/test_figolab.py` | SSID/channel validation, hostapd/dnsmasq generation, dependency mock, sessions, metrics credential-safety, process tracker, cleanup idempotence, config backward compatibility, landing HTML has no password field |
| `tests/test_ui_errors.py` | `parse_menu_index`, EOF/Ctrl+C → BackToMenu/ExitApp, `run_action` swallows unexpected errors |

No physical Wi-Fi hardware is required. Do not claim over-the-air AP/capture was tested unless hardware was actually used.

---

## 11. Known limitations / debt

1. `render_banner()` is a no-op.
2. Lab AP is open (`wpa=0`); it does not clone WPA2 encryption of the target.
3. Portal `logo_path` is stored but not rendered in HTML yet.
4. `traceback` is imported in `modules/ui.py` but unused.
5. Hashcat GPU path can destabilize the **host OS** if the operator installs proprietary NVIDIA drivers incorrectly — outside Figo’s installer.
6. Real AP-mode / monitor-mode behavior is hardware-specific (USB nl80211 recommended).
7. `install.sh` does not `chmod` Python modules under `modules/` (not required; they are imported, not executed as scripts).
8. Clone URL in README still shows `mode5322/figo.git`; GitHub repo is currently `mode5322/Figo`.

---

## 12. Maintenance rule

When changing **any** of: layout, menus, config schema, capture/crack/lab flows, safety, dependencies, tests:

1. Edit `ARCHITECTURE.md` in the same commit.
2. Refresh “Last updated” and the reviewed commit hash.
3. Keep this file factual — no planned features listed as implemented.

Cursor rule: `.cursor/rules/architecture.mdc` (always apply).
