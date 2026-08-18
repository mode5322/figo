# Figo

Terminal Wi-Fi toolkit. Authorized lab use only.

```bash
git clone https://github.com/mode5322/Figo.git
cd Figo
python3 -m pip install -r requirements.txt
chmod +x install.sh figo figo.py
sudo ./install.sh
sudo apt install python3-rich aircrack-ng iw hostapd dnsmasq iproute2 network-manager
figo
```

Without install: `./figo`  
Uninstall: `sudo ./install.sh --uninstall`  
Config: `~/.config/figo/config.json`  
Needs a USB adapter with monitor and AP support. Menu **5** installs missing tools (not GPU drivers).

## Menu

| | |
|---|---|
| 1 | Adapter |
| 2 | Scan / target |
| 3 | Wordlist |
| 4 | Settings |
| 5 | Tools |
| 6 | Capture handshake |
| 7 | Crack capture |
| 8 | Evil Twin Lab |

First run: **1 → 2 → 3 → 5**. Ctrl+C on the main menu exits.

**6** — root. Monitor + deauth capture. WPA3/SAE blocked. Files go to the handshake path in settings.

**7** — aircrack-ng (CPU) by default. Hashcat GPU only if `hashcat -I` already works. `no hashes written` means the capture has no full handshake.

## Evil Twin (8)

| | |
|---|---|
| 1 | Portal text |
| 2 | Lab network (use `10.66.66.1`; avoid `192.168.1.1`) |
| 3 | Preflight / adapter count |
| 4 | Dry-run configs |
| 5 | Awareness lab |
| 6 | Preview page |
| 0 | Back |

**8 → 5:** pick target → confirm network/portal → enter the real Wi-Fi password (memory only) → confirm start. Lab AP + portal start. Second adapter can deauth the real AP; one adapter cannot. Wrong password retries. Correct password logs a boolean, stops the twin, restores the interface. **S** or Ctrl+C stops. Report: `~/figo-reports/`.

Edit the page in **8 → 1**, preview with **8 → 6**. Passwords, cookies, and tokens are not stored.

If Wi-Fi does not return: `nmcli device set <iface> managed yes`

Internals: [`ARCHITECTURE.md`](ARCHITECTURE.md)
