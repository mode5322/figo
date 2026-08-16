"""Figo CLI entry and main loop."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Optional

from modules.capture import action_capture
from modules.config import Settings, load_settings, save_settings
from modules.cracking import action_crack_saved
from modules.exceptions import BackToMenu, ExitApp
from modules.menu import render_menu
from modules.network import scan_networks
from modules.setup_actions import (
    action_discover_and_select_target,
    action_select_interface,
    action_select_wordlist,
    action_show_settings,
)
from modules.tools import action_install_tools, ensure_root, require_interface
from modules.ui import (
    ask,
    clear_screen,
    confirm,
    console,
    pause,
    render_banner,
    report_error,
    run_action,
    warn_and_back,
)


def _evil_twin_api():
    """Adapter so figolab can reuse Figo UI helpers without a circular import graph."""
    return SimpleNamespace(
        BackToMenu=BackToMenu,
        ExitApp=ExitApp,
        ask=ask,
        confirm=confirm,
        pause=pause,
        warn_and_back=warn_and_back,
        clear_screen=clear_screen,
        require_interface=require_interface,
        scan_networks=scan_networks,
        save_settings=save_settings,
        ensure_root=ensure_root,
        run_action=run_action,
    )


def action_evil_twin(settings: Settings) -> None:
    from modules.figolab.evil_twin_menu import action_evil_twin_lab

    action_evil_twin_lab(settings, _evil_twin_api())


def _dispatch_choice(settings: Settings, choice: str) -> None:
    mapping = {
        "1": ("Select adapter", action_select_interface, (settings,)),
        "2": ("Discover networks", action_discover_and_select_target, (settings,)),
        "3": ("Select wordlist", action_select_wordlist, (settings,)),
        "4": ("Show settings", action_show_settings, (settings,)),
        "5": ("Check / install tools", action_install_tools, ()),
        "6": ("Capture handshake", action_capture, (settings,)),
        "7": ("Crack handshake", action_crack_saved, (settings,)),
        "8": ("Evil Twin Lab", action_evil_twin, (settings,)),
    }
    entry = mapping.get(choice)
    if entry is None:
        warn_and_back("Unknown option", "Enter a number from 1 to 8, or press Ctrl+C to exit.")
        return
    label, action, args = entry
    run_action(label, action, *args)


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    resume = ""
    for arg in argv:
        if arg.startswith("--resume="):
            resume = arg.split("=", 1)[1]

    settings = load_settings()
    try:
        if resume == "capture":
            run_action("Capture handshake", action_capture, settings)
        elif resume == "crack":
            run_action("Crack handshake", action_crack_saved, settings)
        elif resume == "install":
            run_action("Check / install tools", action_install_tools)
        elif resume == "evil_twin":
            run_action("Evil Twin Lab", action_evil_twin, settings)
    except BackToMenu:
        pass
    except ExitApp:
        console.print("\n[dim]Goodbye.[/dim]")
        return 0

    while True:
        try:
            clear_screen()
            render_banner(settings)
            render_menu(settings)
            choice = ask("Choose a number", exit_on_interrupt=True).strip()
            if not choice:
                continue
            _dispatch_choice(settings, choice)
        except BackToMenu:
            continue
        except ExitApp:
            console.print("\n[dim]Goodbye.[/dim]")
            return 0
        except Exception as exc:
            report_error(
                "Figo",
                "An unexpected error occurred.",
                detail=str(exc).strip() or exc.__class__.__name__,
            )
            continue
