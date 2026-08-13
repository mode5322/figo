# xfi

Terminal console for lab Wi-Fi setup, handshake capture, and wordlist cracking (aircrack-ng).

Use only on networks you own or have permission to test.

## Install (fixes `xfi: command not found`)

```bash
git clone https://github.com/mode5322/xfi.git
cd xfi
chmod +x install.sh xfi xfi.py
sudo ./install.sh
```

This puts a symlink in `/usr/local/bin/xfi`, so the command works from any directory **as a normal user and as root**.

Then:

```bash
xfi
```

If you already have a terminal open, run `hash -r` or open a new one.

### User-only install (not recommended)

```bash
./install.sh --user
```

That installs to `~/.local/bin/xfi`. Root will **not** see the command (Kali may even suggest `apt install xfe`, which is a different program). Prefer the system install above.

### Uninstall

```bash
sudo ./install.sh --uninstall
```

### Without installing

```bash
xfi
# or
python3 xfi.py

# or
./xfi
```

## Requirements

Python 3 with `rich`. On Kali:

```bash
sudo apt install python3-rich aircrack-ng cowpatty iw
```

Inside the app, menu **5 — Check / install tools** can install the aircrack-ng tools if they are missing.
