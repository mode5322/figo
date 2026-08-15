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

from modules.exceptions import BackToMenu, ExitApp
from modules.ui import parse_menu_index
from modules.figolab.lab_session import (
    LabError,
    cleanup_lab_session,
    detect_lab_dependencies,
    dry_run_lab_configs,
    start_lab_session,
)
from modules.figolab.models import (
    LAB_NETWORK_PRESETS,
    LAB_PACKAGES,
    LabConfig,
    PortalConfig,
    channel_band,
    normalize_lab_network,
    validate_ap_passphrase,
    validate_lab_network,
    validate_portal_port,
    validate_subnet_prefix,
)
from modules.preflight import format_preflight_report, run_preflight

console = Console()


def action_evil_twin_lab(settings: Any, api: Any) -> None:
    """Top-level Evil Twin Lab submenu."""
    run = getattr(api, "run_action", None)
    while True:
        try:
            api.clear_screen()
            table = Table(show_header=False, box=box.SIMPLE, expand=True, padding=(0, 1))
            table.add_column("key", style="bold yellow", width=4)
            table.add_column("label")
            table.add_row("1", "Wi-Fi Lab")
            table.add_row("2", "Security Awareness Lab")
            table.add_row("3", "Configure awareness portal")
            table.add_row("4", "Configure lab network (gateway / DHCP / port / SSID)")
            table.add_row("5", "Dry-run lab setup (show configs, no AP)")
            table.add_row("6", "Adapter / preflight check")
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
            if choice in {"0", ""}:
                return
            if choice == "1":
                if run:
                    run("Wi-Fi Lab", _run_lab_flow, settings, api, mode="wifi")
                else:
                    _run_lab_flow(settings, api, mode="wifi")
            elif choice == "2":
                if run:
                    run("Security Awareness Lab", _run_lab_flow, settings, api, mode="awareness")
                else:
                    _run_lab_flow(settings, api, mode="awareness")
            elif choice == "3":
                if run:
                    run("Configure awareness portal", _configure_portal, settings, api)
                else:
                    _configure_portal(settings, api)
            elif choice == "4":
                if run:
                    run("Configure lab network", _configure_lab_network, settings, api)
                else:
                    _configure_lab_network(settings, api)
            elif choice == "5":
                if run:
                    run("Dry-run lab setup", _dry_run_lab, settings, api)
                else:
                    _dry_run_lab(settings, api)
            elif choice == "6":
                if run:
                    run("Adapter / preflight check", _show_preflight, settings, api)
                else:
                    _show_preflight(settings, api)
            else:
                api.warn_and_back("Unknown option", "Enter 0–6.")
        except BackToMenu:
            return
        except ExitApp:
            raise


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
    require_login = api.confirm(
        "Show a sign-in page with a password field? (value is never stored)",
        default=portal.require_login,
    )
    username_label = portal.login_username_label
    password_label = portal.login_password_label
    button_label = portal.login_button_label
    if require_login:
        username_label = (
            api.ask("Sign-in username label", default=portal.login_username_label)
            or portal.login_username_label
        )
        password_label = (
            api.ask("Sign-in password label", default=portal.login_password_label)
            or portal.login_password_label
        )
        button_label = (
            api.ask("Sign-in button label", default=portal.login_button_label)
            or portal.login_button_label
        )

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
        require_login=require_login,
        login_username_label=username_label.strip(),
        login_password_label=password_label.strip(),
        login_button_label=button_label.strip(),
    )
    try:
        api.save_settings(settings)
    except OSError as exc:
        api.warn_and_back("Could not save settings", str(exc))
        return
    console.print("\n[green]Portal configuration saved.[/green]")
    console.print("[dim]Real passwords are never collected or stored.[/dim]")
    api.pause()


def _lab_network_from_settings(settings: Any) -> dict[str, str]:
    return normalize_lab_network(getattr(settings, "lab_network", None))


def _save_lab_network(settings: Any, api: Any, network: dict[str, str]) -> bool:
    settings.lab_network = normalize_lab_network(network)
    try:
        api.save_settings(settings)
    except OSError as exc:
        api.warn_and_back("Could not save settings", str(exc))
        return False
    return True


def _prompt_custom_lab_network(api: Any, current: dict[str, str]) -> Optional[dict[str, str]]:
    gateway = (
        api.ask("Gateway IP", default=current.get("gateway_ip", "10.66.66.1")).strip()
        or current.get("gateway_ip", "10.66.66.1")
    )
    dhcp_start = (
        api.ask("DHCP range start", default=current.get("dhcp_range_start", "10.66.66.10")).strip()
        or current.get("dhcp_range_start", "10.66.66.10")
    )
    dhcp_end = (
        api.ask("DHCP range end", default=current.get("dhcp_range_end", "10.66.66.100")).strip()
        or current.get("dhcp_range_end", "10.66.66.100")
    )
    prefix = (
        api.ask("Subnet prefix (CIDR)", default=current.get("subnet_prefix", "24")).strip()
        or current.get("subnet_prefix", "24")
    )
    port = (
        api.ask("Portal port", default=current.get("portal_port", "8080")).strip()
        or current.get("portal_port", "8080")
    )
    ap_ssid = api.ask(
        "Lab AP SSID (Enter = use target SSID; optional training variant)",
        default=current.get("ap_ssid", ""),
    ).strip()
    ok, err = validate_lab_network(gateway, dhcp_start, dhcp_end)
    if not ok:
        api.warn_and_back("Invalid lab network", err)
        return None
    ok, err = validate_subnet_prefix(prefix)
    if not ok:
        api.warn_and_back("Invalid subnet prefix", err)
        return None
    ok, err = validate_portal_port(port)
    if not ok:
        api.warn_and_back("Invalid portal port", err)
        return None
    return normalize_lab_network(
        {
            "preset": "custom",
            "gateway_ip": gateway,
            "dhcp_range_start": dhcp_start,
            "dhcp_range_end": dhcp_end,
            "subnet_prefix": prefix,
            "portal_port": port,
            "ap_ssid": ap_ssid,
        }
    )


def _prompt_ap_security(api: Any, current: dict[str, str]) -> Optional[dict[str, str]]:
    """Ask whether the lab AP should be WPA2-secured (padlock) or open."""
    cur_secured = str(current.get("ap_security", "open")).lower() == "wpa2"
    secured = api.confirm(
        "Secure the lab AP with WPA2 (shows a padlock, hides 'insecure network')?",
        default=cur_secured,
    )
    if not secured:
        return {"ap_security": "open", "ap_passphrase": ""}
    passphrase = api.ask(
        "Lab WPA2 passphrase (8–63 chars, shared with participants)",
        default=current.get("ap_passphrase", ""),
    )
    ok, err = validate_ap_passphrase(passphrase or "")
    if not ok:
        api.warn_and_back("Invalid WPA2 passphrase", err)
        return None
    return {"ap_security": "wpa2", "ap_passphrase": passphrase}


def _configure_lab_network(settings: Any, api: Any) -> None:
    """Menu 8 → 4: choose default / home-style / custom gateway+DHCP+port+SSID + security."""
    api.clear_screen()
    current = _lab_network_from_settings(settings)
    cur_sec = "WPA2" if str(current.get("ap_security", "open")).lower() == "wpa2" else "open"
    console.print(
        Panel(
            f"Current gateway : {current['gateway_ip']}/{current.get('subnet_prefix', '24')}\n"
            f"DHCP range      : {current['dhcp_range_start']} – {current['dhcp_range_end']}\n"
            f"Portal port     : {current.get('portal_port', '8080')}\n"
            f"Lab AP SSID     : {current.get('ap_ssid') or '(same as target)'}\n"
            f"AP security     : {cur_sec}\n"
            f"Preset          : {current.get('preset', 'default')}",
            title="Lab network (gateway / DHCP / port / SSID / security)",
            border_style="cyan",
        )
    )
    table = Table(show_header=False, box=box.SIMPLE, expand=True, padding=(0, 1))
    table.add_column("key", style="bold yellow", width=4)
    table.add_column("label")
    table.add_row("1", "Default lab network  ·  10.66.66.1  (DHCP 10.66.66.10–100)")
    table.add_row("2", "Home-style network   ·  192.168.1.1  (DHCP 192.168.1.10–100)")
    table.add_row("3", "Customize gateway, DHCP, prefix, portal port, lab SSID")
    table.add_row("4", "AP security only (WPA2 padlock / open)")
    table.add_row("0", "Back / keep current")
    console.print(Panel(table, title="Choose addressing", border_style="green", box=box.ROUNDED))
    if current.get("preset") == "home":
        console.print(
            "[yellow]Note:[/yellow] 192.168.1.1 often conflicts with real home routers. "
            "Prefer 10.66.66.1 for clean lab use.\n"
        )

    choice = api.ask("Choose a number", default="").strip()
    if choice in {"", "0"}:
        return
    if choice == "1":
        network = dict(LAB_NETWORK_PRESETS["default"])
    elif choice == "2":
        network = dict(LAB_NETWORK_PRESETS["home"])
    elif choice == "3":
        network = _prompt_custom_lab_network(api, current)
        if network is None:
            return
    elif choice == "4":
        network = dict(current)
    else:
        api.warn_and_back("Unknown option", "Enter 0–4.")
        return

    security = _prompt_ap_security(api, current)
    if security is None:
        return
    network.update(security)

    if not _save_lab_network(settings, api, network):
        return
    saved = _lab_network_from_settings(settings)
    console.print(
        f"\n[green]Lab network saved:[/green] gateway [bold]{saved['gateway_ip']}"
        f"/{saved.get('subnet_prefix', '24')}[/bold] · "
        f"DHCP {saved['dhcp_range_start']}–{saved['dhcp_range_end']} · "
        f"portal :{saved.get('portal_port', '8080')}"
    )
    api.pause()


def _show_preflight(settings: Any, api: Any) -> None:
    if not api.require_interface(settings):
        return
    network = _lab_network_from_settings(settings)
    port = int(network.get("portal_port") or 8080)
    report = run_preflight(
        mode="awareness",
        interface=settings.interface,
        required_bins=("hostapd", "dnsmasq", "iw", "ip"),
        portal_port=port,
        check_ap=True,
        check_monitor=True,
        check_dns_port=True,
        require_root=False,
    )
    api.clear_screen()
    console.print(
        Panel(
            format_preflight_report(report),
            title="Adapter / preflight check",
            border_style="green" if report.ok else "yellow",
            box=box.ROUNDED,
        )
    )
    api.pause()


def _dry_run_lab(settings: Any, api: Any) -> None:
    if not api.require_interface(settings):
        return
    row = _pick_target(settings, api)
    if row is None:
        return
    config = _build_lab_config(settings, row, "awareness")
    try:
        hostapd_text, dnsmasq_text, notes = dry_run_lab_configs(config)
    except LabError as exc:
        api.warn_and_back("Dry-run failed", str(exc))
        return
    api.clear_screen()
    console.print(Panel(notes, title="Dry-run summary", border_style="cyan"))
    console.print(Panel(hostapd_text.strip() or "(empty)", title="hostapd.conf", border_style="green"))
    console.print(Panel(dnsmasq_text.strip() or "(empty)", title="dnsmasq.conf", border_style="green"))
    console.print("[dim]No processes started. No interface changes were made.[/dim]")
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
    index = parse_menu_index(choice, max_index=len(rows))
    if index is None:
        if choice.strip():
            api.warn_and_back("Invalid choice", "Enter a number from the network list.")
        return None
    return rows[index - 1]


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
    network = _lab_network_from_settings(settings)
    ap_ssid = (network.get("ap_ssid") or "").strip() or row.get("ssid", "")
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
        ap_ssid=ap_ssid,
        gateway_ip=network["gateway_ip"],
        dhcp_range_start=network["dhcp_range_start"],
        dhcp_range_end=network["dhcp_range_end"],
        subnet_prefix=int(network.get("subnet_prefix") or 24),
        portal_port=int(network.get("portal_port") or 8080),
        ap_security=str(network.get("ap_security") or "open"),
        ap_passphrase=str(network.get("ap_passphrase") or ""),
    )


def _confirm_start(config: LabConfig, api: Any) -> bool:
    ap_sec = "WPA2 (secured / padlock)" if config.is_secured() else "open (clients warn: insecure)"
    login = (
        "Sign-in page shown (password NEVER stored)"
        if config.portal_enabled and config.portal.require_login
        else ("Awareness prompt only" if config.portal_enabled else "Disabled")
    )
    body = (
        f"Target SSID : {config.target_ssid}\n"
        f"Lab AP SSID : {config.effective_ssid()}\n"
        f"Channel     : {config.channel}\n"
        f"AP security : {ap_sec}\n"
        f"Interface   : {config.interface}\n"
        f"Gateway IP  : {config.gateway_ip}/{config.subnet_prefix}\n"
        f"DHCP range  : {config.dhcp_range_start} – {config.dhcp_range_end}\n"
        f"Portal      : {'Enabled' if config.portal_enabled else 'Disabled'} · captive :80 + :{config.portal_port}\n"
        f"Sign-in     : {login}\n"
        f"{'─' * 38}\n"
        "This is an authorized security lab.\n"
        "No real passwords will be collected or stored."
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
    try:
        api.save_settings(settings)
    except OSError as exc:
        api.warn_and_back("Could not save settings", str(exc))
        return

    api.clear_screen()
    _show_target_info(row, settings.interface)
    api.pause("Press Enter to configure the lab AP...")

    network = _lab_network_from_settings(settings)
    console.print(
        Panel(
            f"Gateway IP : {network['gateway_ip']}/{network.get('subnet_prefix', '24')}\n"
            f"DHCP range : {network['dhcp_range_start']} – {network['dhcp_range_end']}\n"
            f"Portal port: {network.get('portal_port', '8080')} (+ captive :80)\n"
            f"Lab SSID   : {network.get('ap_ssid') or '(same as target)'}\n"
            f"AP security: {'WPA2 (padlock)' if str(network.get('ap_security', 'open')).lower() == 'wpa2' else 'open (insecure)'}\n"
            f"Preset     : {network.get('preset', 'default')}",
            title="Lab network",
            border_style="cyan",
        )
    )
    if not api.confirm("Use this lab network (gateway / DHCP / port / SSID / security)?", default=True):
        _configure_lab_network(settings, api)

    config = _build_lab_config(settings, row, mode)

    report = run_preflight(
        mode="awareness" if mode == "awareness" else "lab",
        interface=settings.interface,
        required_bins=("hostapd", "dnsmasq", "iw", "ip"),
        portal_port=config.portal_port,
        check_ap=True,
        check_monitor=False,
        check_dns_port=True,
        require_root=True,
    )
    console.print(
        Panel(
            format_preflight_report(report),
            title="Preflight",
            border_style="green" if report.ok else "yellow",
            box=box.ROUNDED,
        )
    )
    if not report.ok:
        fails = ", ".join(item.name for item in report.blocking_failures())
        if not api.confirm(
            f"Preflight reported problems ({fails}). Continue anyway?",
            default=False,
        ):
            return

    if mode == "awareness":
        console.print(
            Panel(
                f"Organization : {config.portal.organization or '-'}\n"
                f"Portal title : {config.portal.portal_title}\n"
                f"Contact      : {config.portal.security_contact or '-'}\n"
                f"Sign-in page : {'Yes (password never stored)' if config.portal.require_login else 'No (prompt only)'}\n"
                f"Portal port  : {config.portal_port} (+ captive :80)",
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
    security = "WPA2 (secured)" if session.config.is_secured() else "open (insecure)"
    portal_ports = ":80 + :{}".format(session.config.portal_port)
    if session.portal and session.portal.bound_ports:
        portal_ports = " + ".join(f":{p}" for p in session.portal.bound_ports)
    body = (
        f"SSID: {session.config.effective_ssid()}\n"
        f"Channel: {session.config.channel}  ·  Band: {channel_band(session.config.channel)}\n"
        f"Security: {security}\n"
        f"Gateway: {session.config.gateway_ip}/{session.config.subnet_prefix}\n"
        f"DHCP: {session.config.dhcp_range_start} – {session.config.dhcp_range_end}\n"
        f"AP: {ap}\n"
        f"Portal: {portal}  ·  {portal_ports}\n"
        f"Runtime: {session.runtime_sec()}s\n"
        f"{'─' * 42}\n"
        f"Connected devices  : {snap['connected_devices']}\n"
        f"Portal visits      : {snap['portal_visits']}\n"
        f"Sign-in submissions: {snap['login_submissions']}\n"
        f"[red]Passwords entered  : {snap['passwords_entered']}[/red]\n"
        f"Interactions       : {snap['interactions']}\n"
        f"Completed          : {snap['completed']}\n"
        f"{'─' * 42}\n"
        f"[dim]Live behaviour events[/dim]\n"
        f"{_format_events(session.metrics.recent_events(6))}"
    )
    return Panel(
        body,
        title="SECURITY AWARENESS LAB" if session.config.lab_mode == "awareness" else "WIFI LAB",
        subtitle="[S] Stop Assessment  ·  Ctrl+C",
        border_style="green",
        box=box.ROUNDED,
    )


def _format_events(events: list[dict[str, str]]) -> str:
    if not events:
        return "[dim](waiting for clients / portal activity)[/dim]"
    lines: list[str] = []
    for event in events:
        ts = (event.get("ts") or "")[-8:]
        kind = event.get("kind") or "event"
        message = event.get("message") or ""
        lines.append(f"{ts} · {kind}: {message}")
    return "\n".join(lines)


def _live_dashboard(session, api: Any) -> None:
    stop = False

    def _read_key(timeout: float = 0.5) -> str:
        if not sys.stdin.isatty():
            time.sleep(timeout)
            return ""
        try:
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
        except (OSError, termios.error, ValueError):
            time.sleep(timeout)
            return ""

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
