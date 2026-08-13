"""Main menu rendering."""

from __future__ import annotations

from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.table import Table

from modules.config import Settings
from modules.tools import missing_bins
from modules.ui import console, is_wpa3, menu_value


def render_menu(settings: Settings) -> None:
    adapter = menu_value(settings.interface, bool(settings.interface))
    if settings.target.ssid:
        target_label = settings.target.ssid
        if settings.target.bssid:
            target_label = f"{settings.target.ssid}  ({settings.target.bssid})"
        if is_wpa3(settings.target.security):
            target = f"{menu_value(target_label, True)} [yellow]WPA3[/yellow]"
        else:
            target = menu_value(target_label, True)
    else:
        target = menu_value("", False)
    word = menu_value(Path(settings.wordlist).name if settings.wordlist else "", bool(settings.wordlist))

    table = Table(show_header=False, box=box.SIMPLE, expand=True, padding=(0, 1))
    table.add_column("key", style="bold yellow", width=4)
    table.add_column("label")
    table.add_column("value", justify="right", overflow="ellipsis", no_wrap=True)
    missing_n = len(missing_bins())
    tools_status = (
        f"[yellow]{missing_n} missing[/yellow]" if missing_n else "[bold green]all OK[/bold green]"
    )
    table.add_row("", "[bold]Setup[/bold]", "requirment")
    table.add_row("1", "Select a network adapter", adapter)
    table.add_row("2", "Discover networks and select a test target", target)
    table.add_row("3", "Select a password wordlist file", word)
    table.add_row("4", "Show current settings", "")
    table.add_row("5", "Check / install tools", tools_status)
    table.add_row("--", "[bold][red]------------------------[/red][/bold]", "")
    table.add_row("", "[bold]Run[/bold]", "")
    table.add_row("6", "Capture handshake", "")
    table.add_row("7", "Crack a saved handshake", "")
    table.add_row("8", "Evil Twin Lab", "")
    console.print(Panel(table, title="Main menu", subtitle="Ctrl+C to exit", border_style="green", box=box.ROUNDED))

