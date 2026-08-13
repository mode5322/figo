# figo

figo— A terminal-based Wi-Fi security testing toolkit for authorized lab environments.

Use only on networks you own or have permission to test.

## Install 

```bash
git clone https://github.com/mode5322/figo.git
cd figo
chmod +x install.sh figo figo.py
sudo ./install.sh
```

This puts a symlink in `/usr/local/bin/figo`, so the command works from any directory **as a normal user and as root**.

Then:

```bash
figo
```

If you already have a terminal open, run `hash -r` or open a new one.

### User-only install (not recommended)

```bash
./install.sh --user
```

That installs to `~/.local/bin/figo`. Root will **not** see the command (Kali may even suggest `apt install xfe`, which is a different program). Prefer the system install above.

### Uninstall

```bash
sudo ./install.sh --uninstall
```

### Without installing

```bash
figo
# or
python3 figo.py

# or
./figo
```

## Requirements

Python 3 with `rich`. On Kali:

```bash
sudo apt install python3-rich aircrack-ng cowpatty iw
```

Inside the app, menu **5 — Check / install tools** can install the aircrack-ng tools if they are missing.
