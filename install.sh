#!/usr/bin/env bash
# Install figo so the command works for both a normal user and root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
LAUNCHER="$ROOT/figo"
SYSTEM_BIN="/usr/local/bin/figo"

usage() {
  cat <<'EOF'
Usage: ./install.sh [--user] [--uninstall]

  (default)  Install system-wide to /usr/local/bin/figo  (works as user and root)
  --user     Install to ~/.local/bin/figo  (current user only; root will not see it)
  --uninstall  Remove installed command links
EOF
}

user_bin() {
  echo "${HOME}/.local/bin/figo"
}

need_launcher() {
  if [[ ! -f "$LAUNCHER" ]]; then
    echo "error: launcher not found: $LAUNCHER" >&2
    exit 1
  fi
  chmod +x "$LAUNCHER" "$ROOT/figo.py" 2>/dev/null || true
}

link_to() {
  local dest="$1"
  mkdir -p "$(dirname "$dest")"
  ln -sfn "$LAUNCHER" "$dest"
  echo "installed  $dest  ->  $LAUNCHER"
}

remove_if_ours() {
  local dest="$1"
  if [[ -L "$dest" ]]; then
    rm -f "$dest"
    echo "removed    $dest"
  elif [[ -e "$dest" ]]; then
    echo "skip       $dest (not a symlink created by this installer)"
  fi
}

uninstall() {
  remove_if_ours "$(user_bin)"
  if [[ "$(id -u)" -eq 0 ]]; then
    remove_if_ours "$SYSTEM_BIN"
  elif command -v sudo >/dev/null 2>&1; then
    sudo rm -f "$SYSTEM_BIN"
    echo "removed    $SYSTEM_BIN"
  else
    echo "could not remove $SYSTEM_BIN (need root or sudo)" >&2
  fi
}

install_system() {
  need_launcher
  if [[ "$(id -u)" -eq 0 ]]; then
    link_to "$SYSTEM_BIN"
  elif command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p /usr/local/bin
    sudo ln -sfn "$LAUNCHER" "$SYSTEM_BIN"
    echo "installed  $SYSTEM_BIN  ->  $LAUNCHER"
  else
    echo "sudo not found; installing for the current user only." >&2
    link_to "$(user_bin)"
    echo "warning: root shells will not find 'figo'. Re-run as root: ./install.sh" >&2
    return
  fi
  hash -r 2>/dev/null || true
  echo
  echo "Done. Open a new terminal (or run: hash -r) then:"
  echo "  figo"
}

install_user() {
  need_launcher
  link_to "$(user_bin)"
  echo
  echo "Installed for the current user only."
  echo "Root shells will not see this command. Prefer: sudo ./install.sh"
}

case "${1:-}" in
  -h|--help) usage ;;
  --uninstall) uninstall ;;
  --user) install_user ;;
  "") install_system ;;
  *) usage; exit 1 ;;
esac
