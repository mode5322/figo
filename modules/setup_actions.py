"""Setup menu actions (adapter, target, wordlist, settings)."""

from __future__ import annotations

import os
from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.table import Table

from modules.config import Settings, Target, save_settings
from modules.constants import CONFIG_FILE, DEFAULT_HANDSHAKE_DIR
from modules.network import iface_state, scan_networks, wireless_interfaces
from modules.tools import require_interface
from modules.ui import ask, clear_screen, console, is_wpa3, pause, parse_menu_index, render_banner, warn_and_back
from modules.wordlists import discover_wordlists, wordlist_info


def action_select_interface(settings: Settings) -> None:
    clear_screen()
    render_banner(settings)
    ifaces = wireless_interfaces()
    if not ifaces:
        warn_and_back(
            "No wireless adapter",
            "No wireless interface (wlan) was found.\n"
            "Make sure the adapter is enabled and not blocked by rfkill.",
        )
        return

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("#", style="yellow", width=4)
    table.add_column("Interface", style="cyan")
    table.add_column("State")
    for i, name in enumerate(ifaces, 1):
        mark = "  <- current" if name == settings.interface else ""
        table.add_row(str(i), name + mark, iface_state(name))
    console.print(Panel(table, title="Wireless adapters", border_style="cyan"))

    choice = ask("Adapter number (or Enter to go back)")
    index = parse_menu_index(choice, max_index=len(ifaces))
    if index is None:
        if choice.strip():
            warn_and_back("Invalid choice", "Enter a number from the list.")
        return

    settings.interface = ifaces[index - 1]
    try:
        save_settings(settings)
    except OSError as exc:
        warn_and_back("Could not save settings", str(exc))
        return
    console.print(f"\n[green]Adapter selected:[/green] [bold]{settings.interface}[/bold]")
    pause()


def action_select_wordlist(settings: Settings) -> None:
    clear_screen()
    render_banner(settings)
    discovered = discover_wordlists()

    if discovered:
        table = Table(box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("#", style="yellow", width=4)
        table.add_column("File", style="cyan")
        table.add_column("Details", style="dim")
        for i, path in enumerate(discovered, 1):
            mark = "  <- current" if str(path) == settings.wordlist else ""
            table.add_row(str(i), str(path) + mark, wordlist_info(path))
        console.print(Panel(table, title="Discovered wordlists", border_style="cyan"))
        console.print("[dim]Or type a full path to another file.[/dim]\n")

    raw = ask("List number or file path (Enter to go back)").strip()
    if not raw:
        return

    if raw.isdigit() and discovered and 1 <= int(raw) <= len(discovered):
        path = discovered[int(raw) - 1]
    else:
        path = Path(os.path.expanduser(raw)).resolve()

    if not path.is_file():
        warn_and_back("File not found", f"Invalid path or not a file:\n{path}")
        return

    settings.wordlist = str(path)
    try:
        save_settings(settings)
    except OSError as exc:
        warn_and_back("Could not save settings", str(exc))
        return
    console.print(f"\n[green]Wordlist selected:[/green] [bold]{path}[/bold]")
    console.print(f"[dim]{wordlist_info(path)}[/dim]")
    pause()


def action_discover_and_select_target(settings: Settings) -> None:
    if not require_interface(settings):
        return

    clear_screen()
    render_banner(settings)
    console.print("[dim]Scanning visible networks...[/dim]")
    rows, error = scan_networks(settings.interface)
    if error:
        warn_and_back("Scan failed", error)
        return
    if not rows:
        warn_and_back("No results", "No networks were found on the selected adapter.")
        return

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("#", style="yellow", width=4)
    table.add_column("SSID")
    table.add_column("BSSID", style="dim")
    table.add_column("CH", justify="right")
    table.add_column("Signal", justify="right")
    table.add_column("Security")
    for i, row in enumerate(rows, 1):
        mark = " <-" if row["bssid"] == settings.target.bssid and settings.target.bssid else ""
        table.add_row(
            str(i),
            row["ssid"] + mark,
            row["bssid"],
            row["channel"],
            row["signal"],
            row["security"],
        )
    console.print(Panel(table, title=f"Networks on {settings.interface}", border_style="green"))

    choice = ask("Target number (Enter to go back)")
    index = parse_menu_index(choice, max_index=len(rows))
    if index is None:
        if choice.strip():
            warn_and_back("Invalid choice", "Enter a number from the network list.")
        return

    picked = rows[index - 1]
    settings.target = Target(
        ssid=picked["ssid"],
        bssid=picked["bssid"],
        channel=picked["channel"],
        signal=picked["signal"],
        security=picked["security"],
    )
    try:
        save_settings(settings)
    except OSError as exc:
        warn_and_back("Could not save settings", str(exc))
        return
    console.print(
        f"\n[green]Target selected:[/green] [bold]{settings.target.ssid}[/bold] "
        f"[dim]({settings.target.bssid})[/dim]"
    )
    pause()


def action_show_settings(settings: Settings) -> None:
    clear_screen()
    render_banner(settings)
    table = Table(box=box.ROUNDED, expand=True, show_header=False)
    table.add_column("k", style="bold", width=18)
    table.add_column("v")
    table.add_row("Adapter", settings.interface or "[red]not set[/red]")
    table.add_row("Wordlist", settings.wordlist or "[red]not set[/red]")
    if settings.wordlist:
        table.add_row("File details", wordlist_info(Path(settings.wordlist)))
    table.add_row("SSID", settings.target.ssid or "[red]not set[/red]")
    table.add_row("BSSID", settings.target.bssid or "-")
    table.add_row("Channel", settings.target.channel or "-")
    sec = settings.target.security or "-"
    table.add_row("Security", f"[yellow]{sec}[/yellow]" if is_wpa3(sec) else sec)
    table.add_row("Handshake dir", settings.handshake_dir or DEFAULT_HANDSHAKE_DIR)
    portal = settings.portal
    if hasattr(portal, "to_dict"):
        portal = portal.to_dict()
    if not isinstance(portal, dict):
        portal = {}
    table.add_row("Awareness portal", "enabled" if portal.get("enabled", True) else "disabled")
    if portal.get("organization"):
        table.add_row("Organization", str(portal.get("organization")))
    lab_network = settings.lab_network if isinstance(settings.lab_network, dict) else {}
    if lab_network.get("gateway_ip"):
        table.add_row("Lab gateway", str(lab_network.get("gateway_ip")))
        table.add_row(
            "Lab DHCP",
            f"{lab_network.get('dhcp_range_start', '-')} – {lab_network.get('dhcp_range_end', '-')}",
        )
    table.add_row("Config file", str(CONFIG_FILE))
    console.print(table)
    pause()

