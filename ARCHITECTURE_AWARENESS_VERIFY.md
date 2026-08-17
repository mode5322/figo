# Awareness password-verify flow (2026-08-17)

Supplement until `ARCHITECTURE.md` is updated in-repo.

## Operator flow (menu 8 → 5)

1. Disconnect operator adapter from corporate Wi-Fi (`nmcli device disconnect` in `prepare_interface`).
2. Start evil-twin AP (`hostapd` + `dnsmasq` + captive portal).
3. Client connects → captive portal sign-in page opens automatically.
4. Client submits password → spinner page polls `/login/result`.
5. Background thread compares password in memory to operator-provided corporate PSK (`getpass` at lab start; never saved).
6. Wrong password → error page with retry.
7. Correct password → success page; live log records `correct_password=true`; lab auto-stops and restores original network state.

## Config

`portal.verify_target_password` (default `true`) in `~/.config/figo/config.json`.

## Deauth (second adapter)

- Requires **2+ wireless adapters** (one for twin AP, one for monitor/deauth).
- Option **3** shows adapter count with orange note when only one is present.
- During lab (option 5): periodic `aireplay-ng --deauth` toward target BSSID.
- Uses `iw` monitor mode on the second adapter (no `airmon-ng check kill` — would kill the lab AP).

## Modules

- `modules/figolab/lab_deauth.py`
- `modules/figolab/awareness/password_verify.py`
- `modules/figolab/awareness_lab_ui.py` (patches `evil_twin_menu` handlers)
- Updated: `portal_server.py`, `portal_pages.py`, `awareness_metrics.py`, `lab_session.py`, `wireless_interface.py`
