"""External tool detection, installation, and process helpers."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from rich import box
from rich.panel import Panel
from rich.table import Table

from modules.config import load_settings
from modules.constants import ENTRY_SCRIPT, OPTIONAL_BINS, REQUIRED_BINS, TOOL_PACKAGES
from modules.ui import clear_screen, confirm, console, pause, render_banner, warn_and_back


def which_or_none(*names: str) -> Optional[str]:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def missing_bins(names: tuple[str, ...] | None = None) -> list[str]:
    check = names if names is not None else REQUIRED_BINS + OPTIONAL_BINS
    return [name for name in check if not which_or_none(name)]


def packages_for(bins: list[str]) -> list[str]:
    pkgs: list[str] = []
    blocked = {"nvidia", "cuda", "nvidia-driver", "nvidia-cuda-toolkit"}
    for name in bins:
        pkg = TOOL_PACKAGES.get(name, name)
        # Figo must never pull GPU proprietary driver stacks via apt.
        if pkg.lower() in blocked or pkg.lower().startswith("nvidia-"):
            continue
        if pkg not in pkgs:
            pkgs.append(pkg)
    return pkgs


def require_bins(names: tuple[str, ...]) -> bool:
    missing = missing_bins(names)
    if not missing:
        return True
    pkgs = packages_for(missing)
    warn_and_back(
        "Missing tools",
        "These commands are not installed:\n"
        + ", ".join(f"[bold]{n}[/bold]" for n in missing)
        + "\n\nChoose [bold]5 — Check / install tools[/bold] to install:\n"
        + ", ".join(pkgs),
    )
    return False


def run_cmd(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return proc.returncode, out
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 1, f"Timed out after {timeout}s: {' '.join(cmd)}"


def ensure_root(resume: str) -> bool:
    if os.geteuid() == 0:
        return True
    sudo = which_or_none("sudo")
    if not sudo:
        warn_and_back(
            "Root required",
            "This action needs root, and [bold]sudo[/bold] was not found.\n"
            "Run the tool as root, then try again.",
        )
        return False
    script = str(ENTRY_SCRIPT)
    console.print("\n[yellow]Root required — restarting with sudo...[/yellow]\n")
    try:
        os.execvp(
            sudo,
            [sudo, "-E", sys.executable, script, f"--resume={resume}"],
        )
    except OSError as exc:
        warn_and_back("sudo failed", str(exc))
    return False


def require_interface(settings: Settings) -> bool:
    if settings.interface:
        return True
    warn_and_back(
        "Network adapter required",
        "No network adapter is selected yet.\n"
        "Choose [bold]1 — Select a network adapter[/bold] from the menu,\n"
        "then try again.",
    )
    return False


def require_capture_ready(settings: Settings) -> bool:
    missing: list[str] = []
    if not settings.interface:
        missing.append("network adapter (menu 1)")
    if not settings.target.bssid:
        missing.append("test target BSSID (menu 2)")
    if not settings.target.channel or settings.target.channel in {"-", "?"}:
        missing.append("target channel (menu 2)")
    if missing:
        warn_and_back(
            "Settings incomplete",
            "Set the following, then try Capture again:\n\n"
            + "\n".join(f"• {item}" for item in missing),
        )
        return False
    return True


def require_wordlist(settings: Settings) -> bool:
    wordlist = Path(settings.wordlist) if settings.wordlist else None
    if wordlist and wordlist.is_file():
        return True
    warn_and_back(
        "Wordlist required",
        "No password wordlist is selected yet.\n"
        "Choose [bold]3 — Select a password wordlist file[/bold] from the menu,\n"
        "then try again.",
    )
    return False


def action_install_tools() -> None:
    if not ensure_root("install"):
        return

    clear_screen()
    render_banner(load_settings())
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Command")
    table.add_column("Package")
    table.add_column("Need")
    table.add_column("Status")
    for name in REQUIRED_BINS + OPTIONAL_BINS:
        found = which_or_none(name)
        need = "required" if name in REQUIRED_BINS else "optional"
        status = f"[bold green]{found}[/bold green]" if found else "[yellow]missing[/yellow]"
        table.add_row(name, TOOL_PACKAGES[name], need, status)
    console.print(Panel(table, title="Tool check", border_style="cyan"))

    missing = missing_bins()
    if not missing:
        console.print("\n[green]All tools are installed.[/green]")
        pause()
        return

    pkgs = packages_for(missing)
    apt = which_or_none("apt-get")
    if not apt:
        warn_and_back(
            "No apt-get",
            "Could not find apt-get. Install these packages with your package manager:\n"
            + " ".join(pkgs),
        )
        return

    console.print(f"\nMissing packages: [bold]{' '.join(pkgs)}[/bold]\n")
    console.print(
        "[dim]Note: Figo installs tool packages only (e.g. hashcat). "
        "It never installs NVIDIA/AMD GPU drivers.[/dim]\n"
    )
    if not confirm("Install with apt-get now?", default=True):
        return

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    console.print("\n[dim]apt-get update...[/dim]")
    update = subprocess.run([apt, "update"], env=env)
    console.print("\n[dim]apt-get install -y " + " ".join(pkgs) + "...[/dim]\n")
    install = subprocess.run([apt, "install", "-y", *pkgs], env=env)
    if update.returncode != 0 or install.returncode != 0:
        warn_and_back(
            "Install failed",
            "apt-get reported an error. Fix the package manager, then try option 5 again.",
        )
        return

    still = missing_bins()
    if still:
        warn_and_back(
            "Still missing",
            "Installed packages, but these commands are still not on PATH:\n"
            + ", ".join(still),
        )
        return

    console.print("\n[green]All tools are now installed.[/green]")
    pause()

