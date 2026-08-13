"""Evil Twin Lab CLI — Wi-Fi Lab and Security Awareness Lab."""

from __future__ import annotations

import select
import sys
import termios
import time
import tty
from typing import Any, Optional

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from modules.figolab.lab_session import (
    LabError,
    cleanup_lab_session,
    detect_lab_dependencies,
    start_lab_session,
)
from modules.figolab.models import LAB_PACKAGES, LabConfig, PortalConfig, channel_band

console = Console()


def action_evil_twin_lab(settings: Any, api: Any) -> None:
    """Top-level Evil Twin Lab submenu."""
    while True:
        api.clear_screen()
        table = Table(show_header=False, box=box.SIMPLE, expand=True, padding=(0, 1))
        table.add_column("key", style="bold yellow", width=4)
        table.add_column("label")
        table.add_row("1", "Wi-Fi Lab")
        table.add_row("2", "Security Awareness Lab")
        table.add_row("3", "Configure awareness portal")
        table.add_row("0", "Back")
        console.print(
            Panel(
                table,
                title="Evil Twin Lab",
                subtitle="Authorized lab use only",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        choice = api.ask("Choose a number").strip()
        if choice == "0" or choice == "":
            return
        if choice == "1":
            _run_lab_flow(settings, api, mode="wifi")
        elif choice == "2":
            _run_lab_flow(settings, api, mode="awareness")
        elif choice == "3":
            _configure_portal(settings, api)
        else:
            api.warn_and_back("Unknown option", "Use 0–3.")


def _portal_from_settings(settings: Any) -> PortalConfig:
    portal = getattr(settings, "portal", None)
    if isinstance(portal, PortalConfig):
        return portal
    if isinstance(portal, dict):
        return PortalConfig.from_dict(portal)
    return PortalConfig()


def _configure_portal(settings: Any, api: Any) -> None:
    api.clear_screen()
    portal = _portal_from_settings(settings)
    console.print(Panel("Security Awareness Portal", border_style="cyan"))
    enabled = api.confirm("Enable portal by default?", default=portal.enabled)
    organization = api.ask("Organization name", default=portal.organization) or portal.organization
    title = api.ask("Portal title", default=portal.portal_title) or portal.portal_title
    training = api.ask("Training message", default=portal.training_message) or portal.training_message
    contact = api.ask("Security contact", default=portal.security_contact) or portal.security_contact
    educational = (
        api.ask("Educational message", default=portal.educational_message) or portal.educational_message
    )
    training_value = api.ask(
        "Optional fake training value (never a real password)",
        default=portal.training_value,
    )
    logo = api.ask("Logo path (optional)", default=portal.logo_path) or portal.logo_path

    settings.portal = PortalConfig(
        enabled=enabled,
        organization=organization.strip(),
        portal_title=title.strip(),
        training_message=training.strip(),
        security_contact=contact.strip(),
        educational_message=educational.strip(),
        training_value=(training_value or "").strip(),
        logo_path=logo.strip(),
        session_ttl_sec=portal.session_ttl_sec,
    )
    api.save_settings(settings)
    console.print("\n[green]Portal configuration saved.[/green]")
    console.print("[dim]Real passwords are never collected or stored.[/dim]")
    api.pause()


def _ensure_lab_tools(api: Any) -> bool:
    missing = detect_lab_dependencies()
    if not missing:
        return True
    pkgs = [LAB_PACKAGES.get(name, name) for name in missing]
    api.warn_and_back(
        "Missing lab tools",
        "Required dependency not found: "
        + ", ".join(f"[bold]{n}[/bold]" for n in missing)
        + "\n\nInstall packages (menu 5 or apt):\n"
        + ", ".join(pkgs)
        + "\n\nFigo will not silently install packages from this menu.",
    )
    return False


def _pick_target(settings: Any, api: Any) -> Optional[dict[str, str]]:
    if not api.require_interface(settings):
        return None
    api.clear_screen()
    console.print("[dim]Scanning visible networks...[/dim]")
    rows, error = api.scan_networks(settings.interface)
    if error:
        api.warn_and_back("Scan failed", error)
        return None
    if not rows:
        api.warn_and_back("No results", "No networks were found on the selected adapter.")
        return None

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("#", style="yellow", width=4)
    table.add_column("SSID")
    table.add_column("BSSID", style="dim")
    table.add_column("CH", justify="right")
    table.add_column("Band")
    table.add_column("Signal", justify="right")
    table.add_column("Security")
    table.add_column("Iface", style="dim")
    for i, row in enumerate(rows, 1):
        table.add_row(
            str(i),
            row["ssid"],
            row["bssid"],
            row["channel"],
            channel_band(row["channel"]),
            row["signal"],
            row["security"],
            settings.interface,
        )
    console.print(Panel(table, title=f"Authorized target selection · {settings.interface}", border_style="green"))
    choice = api.ask("Target number (Enter to go back)")
    if not choice.strip():
        return None
    if not choice.isdigit() or not (1 <= int(choice) <= len(rows)):
        api.warn_and_back("Invalid choice", "Enter a number from the network list.")
        return None
    return rows[int(choice) - 1]


def _show_target_info(row: dict[str, str], interface: str) -> None:
    table = Table(box=box.ROUNDED, expand=True, show_header=False)
    table.add_column("k", style="bold", width=14)
    table.add_column("v")
    table.add_row("SSID", row.get("ssid", ""))
    table.add_row("BSSID", row.get("bssid", ""))
    table.add_row("Channel", row.get("channel", ""))
    table.add_row("Band", channel_band(row.get("channel", "")))
    table.add_row("Security", row.get("security", "-"))
    table.add_row("Signal", row.get("signal", "-"))
    table.add_row("Interface", interface)
    console.print(Panel(table, title="Target information", border_style="cyan"))


def _build_lab_config(settings: Any, row: dict[str, str], mode: str) -> LabConfig:
    portal = _portal_from_settings(settings)
    portal_enabled = mode == "awareness" and portal.enabled
    return LabConfig(
        target_ssid=row.get("ssid", ""),
        target_bssid=row.get("bssid", ""),
        channel=str(row.get("channel", "")),
        security=row.get("security", "") or "open",
        interface=settings.interface,
        ap_interface=settings.interface,
        lab_mode=mode,
        portal_enabled=portal_enabled,
        portal=portal,
        ap_ssid=row.get("ssid", ""),
    )


def _confirm_start(config: LabConfig, api: Any) -> bool:
    body = (
        f"Target SSID : {config.effective_ssid()}\n"
        f"Channel     : {config.channel}\n"
        f"Security    : {config.security}\n"
        f"Interface   : {config.interface}\n"
        f"Portal      : {'Enabled' if config.portal_enabled else 'Disabled'}\n"
        f"{'─' * 38}\n"
        "This is an authorized security lab.\n"
        "No real passwords will be collected."
    )
    console.print(Panel(body, title="EVIL TWIN LAB", border_style="yellow", box=box.ROUNDED))
    return api.confirm("Start assessment?", default=False)


def _run_lab_flow(settings: Any, api: Any, *, mode: str) -> None:
    if not api.ensure_root("evil_twin"):
        return
    if not _ensure_lab_tools(api):
        return

    row = _pick_target(settings, api)
    if row is None:
        return

    # Persist selected target into existing settings for consistency.
    settings.target.ssid = row.get("ssid", "")
    settings.target.bssid = row.get("bssid", "")
    settings.target.channel = row.get("channel", "")
    settings.target.signal = row.get("signal", "")
    settings.target.security = row.get("security", "")
    api.save_settings(settings)

    api.clear_screen()
    _show_target_info(row, settings.interface)
    api.pause("Press Enter to configure the lab AP...")

    config = _build_lab_config(settings, row, mode)
    if mode == "awareness":
        console.print(
            Panel(
                f"Organization : {config.portal.organization or '-'}\n"
                f"Portal title : {config.portal.portal_title}\n"
                f"Contact      : {config.portal.security_contact or '-'}\n"
                f"Portal port  : {config.portal_port}",
                title="Awareness portal configuration",
                border_style="cyan",
            )
        )
        if not api.confirm("Use this portal configuration?", default=True):
            _configure_portal(settings, api)
            config = _build_lab_config(settings, row, mode)

    api.clear_screen()
    if not _confirm_start(config, api):
        console.print("[dim]Assessment cancelled.[/dim]")
        api.pause()
        return

    session = None
    try:
        console.print("\n[dim]Starting controlled lab AP...[/dim]")
        session = start_lab_session(config, enable_portal=(mode == "awareness"))
        console.print("[green]Lab AP started.[/green]")
        if session.portal_active and session.portal:
            console.print(f"[dim]Awareness portal:[/dim] {session.portal.url}")
        api.pause("Press Enter for live dashboard (S or Ctrl+C to stop)...")
        _live_dashboard(session, api)
    except LabError as exc:
        api.warn_and_back("Lab failed", str(exc))
    except api.BackToMenu:
        cleanup_lab_session(session)
        raise
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping assessment...[/yellow]")
    finally:
        cleanup_lab_session(session)
        console.print("[green]Cleanup complete. Original network state restore attempted.[/green]")
        api.pause()


def _dashboard_renderable(session) -> Panel:
    session.refresh_client_count()
    snap = session.metrics.snapshot()
    ap = "Active" if session.ap_active and session.tracker.alive("hostapd") else "Down"
    portal = "Active" if session.portal_active else ("Disabled" if session.config.lab_mode == "wifi" else "Down")
    body = (
        f"SSID: {session.config.effective_ssid()}\n"
        f"Channel: {session.config.channel}  ·  Band: {channel_band(session.config.channel)}\n"
        f"AP: {ap}\n"
        f"Portal: {portal}\n"
        f"Runtime: {session.runtime_sec()}s\n"
        f"{'─' * 42}\n"
        f"Connected devices : {snap['connected_devices']}\n"
        f"Portal visits     : {snap['portal_visits']}\n"
        f"Interactions      : {snap['interactions']}\n"
        f"Completed         : {snap['completed']}"
    )
    return Panel(
        body,
        title="SECURITY AWARENESS LAB" if session.config.lab_mode == "awareness" else "WIFI LAB",
        subtitle="[S] Stop Assessment  ·  Ctrl+C",
        border_style="green",
        box=box.ROUNDED,
    )


def _live_dashboard(session, api: Any) -> None:
    stop = False

    def _read_key(timeout: float = 0.5) -> str:
        if not sys.stdin.isatty():
            time.sleep(timeout)
            return ""
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if ready:
                return sys.stdin.read(1)
            return ""
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    try:
        with Live(_dashboard_renderable(session), console=console, refresh_per_second=4) as live:
            while not stop:
                if not session.tracker.alive("hostapd"):
                    console.print("\n[red][ERROR] Lab AP process exited unexpectedly.[/red]")
                    break
                key = _read_key(0.4)
                if key.lower() == "s":
                    stop = True
                    break
                live.update(_dashboard_renderable(session))
    except KeyboardInterrupt:
        pass
