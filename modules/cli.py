"""Figo CLI entry and main loop."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Optional

from modules.capture import action_capture
from modules.config import Settings, load_settings, save_settings
from modules.cracking import action_crack_saved
from modules.exceptions import BackToMenu
from modules.menu import render_menu
from modules.network import scan_networks
from modules.setup_actions import (
    action_discover_and_select_target,
    action_select_interface,
    action_select_wordlist,
    action_show_settings,
)
from modules.tools import action_install_tools, ensure_root, require_interface
from modules.ui import ask, clear_screen, confirm, console, pause, render_banner, warn_and_back


def _evil_twin_api():
    """Adapter so figolab can reuse Figo UI helpers without a circular import graph."""
    return SimpleNamespace(
        BackToMenu=BackToMenu,
        ask=ask,
        confirm=confirm,
        pause=pause,
        warn_and_back=warn_and_back,
        clear_screen=clear_screen,
        require_interface=require_interface,
        scan_networks=scan_networks,
        save_settings=save_settings,
        ensure_root=ensure_root,
    )


def action_evil_twin(settings: Settings) -> None:
    from modules.figolab.evil_twin import action_evil_twin_lab

    action_evil_twin_lab(settings, _evil_twin_api())


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    resume = ""
    for arg in argv:
        if arg.startswith("--resume="):
            resume = arg.split("=", 1)[1]

    settings = load_settings()
    try:
        if resume == "capture":
            action_capture(settings)
        elif resume == "crack":
            action_crack_saved(settings)
        elif resume == "install":
            action_install_tools()
        elif resume == "evil_twin":
            action_evil_twin(settings)
    except BackToMenu:
        pass
    except KeyboardInterrupt:
        console.print("\n[dim]Goodbye.[/dim]")
        return 0

    while True:
        try:
            clear_screen()
            render_banner(settings)
            render_menu(settings)
            choice = ask("Choose a number", exit_on_interrupt=True).strip()
            if choice == "1":
                action_select_interface(settings)
            elif choice == "2":
                action_discover_and_select_target(settings)
            elif choice == "3":
                action_select_wordlist(settings)
            elif choice == "4":
                action_show_settings(settings)
            elif choice == "5":
                action_install_tools()
            elif choice == "6":
                action_capture(settings)
            elif choice == "7":
                action_crack_saved(settings)
            elif choice == "8":
                action_evil_twin(settings)
            else:
                warn_and_back("Unknown option", "Use 1–8. Ctrl+C to exit.")
        except BackToMenu:
            continue
        except KeyboardInterrupt:
            console.print("\n[dim]Goodbye.[/dim]")
            return 0

