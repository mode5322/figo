"""Awareness-lab UI extensions (password verify flow).

Applied at import time because ``evil_twin_menu.py`` may be read-only in some
environments. Patches replace selected handlers on that module.
"""

from __future__ import annotations

import getpass
from typing import Any

from rich import box
from rich.panel import Panel
from rich.table import Table

from modules.figolab.lab_config import PortalConfig
from modules.figolab.lab_session import (
    LabError,
    build_session_report,
    cleanup_lab_session,
    save_session_report,
    start_lab_session,
)
from modules.network import wireless_interfaces
from modules.preflight import format_preflight_report, run_preflight
from modules.ui import parse_menu_index


def apply_awareness_lab_patches() -> None:
    import modules.figolab.evil_twin_menu as menu

    menu._configure_portal = _configure_portal
    menu._show_preflight = _show_preflight
    menu._confirm_start = _confirm_start
    menu._run_lab_flow = _run_lab_flow
    menu._live_dashboard = _live_dashboard
    menu._dashboard_renderable = _dashboard_renderable
    menu._maybe_save_report = _maybe_save_report


def _adapter_summary() -> tuple[int, list[str]]:
    ifaces = wireless_interfaces()
    return len(ifaces), ifaces


def _show_preflight(settings: Any, api: Any) -> None:
    import modules.figolab.evil_twin_menu as menu

    if not api.require_interface(settings):
        return
    count, ifaces = _adapter_summary()
    network = menu._lab_network_from_settings(settings)
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
    adapter_lines = (
        f"Detected wireless adapters: [bold]{count}[/bold]\n"
        + (f"Names: {', '.join(ifaces)}" if ifaces else "No wireless interfaces found.")
    )
    if count < 2:
        adapter_lines += (
            "\n\n[orange3]Note: disconnecting employees from the real corporate AP "
            "(deauth) requires a second adapter. With one adapter, the twin AP "
            "runs but clients may stay on the original network.[/orange3]"
        )
    else:
        lab = settings.interface
        others = [i for i in ifaces if i != lab]
        adapter_lines += (
            f"\n\n[dim]Lab AP adapter: {lab} · Deauth candidate(s): "
            f"{', '.join(others) or 'none'}[/dim]"
        )
    menu.console.print(
        Panel(
            adapter_lines,
            title="Wireless adapters",
            border_style="orange3" if count < 2 else "cyan",
            box=box.ROUNDED,
        )
    )
    menu.console.print(
        Panel(
            format_preflight_report(report),
            title="Adapter / preflight check",
            border_style="green" if report.ok else "yellow",
            box=box.ROUNDED,
        )
    )
    api.pause()


def _configure_portal(settings: Any, api: Any) -> None:
    import modules.figolab.evil_twin_menu as menu

    api.clear_screen()
    portal = menu._portal_from_settings(settings)
    menu.console.print(Panel("Security Awareness Portal", border_style="cyan"))
    enabled = api.confirm("Enable portal by default?", default=portal.enabled)
    title = api.ask("Portal title", default=portal.portal_title) or portal.portal_title
    training = api.ask("Training message", default=portal.training_message) or portal.training_message
    contact = api.ask("Security contact", default=portal.security_contact) or portal.security_contact
    require_login = api.confirm(
        "Show a sign-in page with a password field?",
        default=portal.require_login,
    )
    verify_password = portal.verify_target_password
    if require_login:
        verify_password = api.confirm(
            "Verify submitted password against the real corporate network?",
            default=portal.verify_target_password,
        )
    password_label = portal.login_password_label
    button_label = portal.login_button_label
    if require_login:
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
        organization="",
        portal_title=title.strip(),
        training_message=training.strip(),
        security_contact=contact.strip(),
        educational_message="",
        training_value="",
        logo_path="",
        session_ttl_sec=portal.session_ttl_sec,
        require_login=require_login,
        verify_target_password=verify_password if require_login else False,
        login_username_label="",
        login_password_label=password_label.strip(),
        login_button_label=button_label.strip(),
    )
    try:
        api.save_settings(settings)
    except OSError as exc:
        api.warn_and_back("Could not save settings", str(exc))
        return
    menu.console.print("\n[green]Portal configuration saved.[/green]")
    api.pause()


def _confirm_start(config, api: Any) -> bool:
    import modules.figolab.evil_twin_menu as menu

    ap_sec = "WPA2 (secured / padlock)" if config.is_secured() else "open (clients warn: insecure)"
    login = (
        "Sign-in + verify against real network (password never stored)"
        if config.portal_enabled and config.portal.require_login and config.portal.verify_target_password
        else (
            "Sign-in page shown (password NEVER stored)"
            if config.portal_enabled and config.portal.require_login
            else ("Awareness prompt only" if config.portal_enabled else "Disabled")
        )
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
        f"Deauth      : {config.deauth_interface + ' (active)' if config.deauth_enabled else 'unavailable (single adapter)'}\n"
        f"{'─' * 38}\n"
        "This is an authorized security lab.\n"
        "Submitted passwords are checked in memory only and never stored."
    )
    menu.console.print(Panel(body, title="EVIL TWIN LAB", border_style="yellow", box=box.ROUNDED))
    _print_deauth_note(config, menu)
    return api.confirm("Start assessment?", default=False)


def _print_deauth_note(config, menu) -> None:
    if config.deauth_enabled and config.deauth_interface:
        menu.console.print(
            Panel(
                f"Deauth adapter : {config.deauth_interface}\n"
                f"Target BSSID   : {config.target_bssid or '-'}\n"
                "Periodic deauth frames will disconnect clients from the real corporate AP "
                "so they can join the lab twin.",
                title="Client deauth",
                border_style="orange3",
                box=box.ROUNDED,
            )
        )
    else:
        menu.console.print(
            Panel(
                "[orange3]Only one wireless adapter (or deauth disabled).[/orange3]\n"
                "Employees may remain connected to the original corporate network.\n"
                "Use a second USB Wi-Fi adapter for automatic client disconnection.",
                title="Client deauth unavailable",
                border_style="orange3",
                box=box.ROUNDED,
            )
        )


def _configure_deauth(config, settings: Any, api: Any) -> None:
    import modules.figolab.evil_twin_menu as menu

    count, ifaces = _adapter_summary()
    ap_iface = settings.interface
    others = [i for i in ifaces if i != ap_iface]
    if not others:
        config.deauth_enabled = False
        config.deauth_interface = ""
        return

    if len(others) == 1:
        config.deauth_interface = others[0]
    else:
        table = Table(show_header=False, box=box.SIMPLE, expand=True, padding=(0, 1))
        table.add_column("key", style="bold yellow", width=4)
        table.add_column("label")
        for i, name in enumerate(others, 1):
            table.add_row(str(i), name)
        menu.console.print(
            Panel(
                table,
                title=f"Choose deauth adapter (lab AP uses {ap_iface})",
                border_style="orange3",
                box=box.ROUNDED,
            )
        )
        choice = api.ask("Deauth adapter number", default="1").strip()
        index = parse_menu_index(choice, max_index=len(others))
        if index is None:
            config.deauth_interface = others[0]
        else:
            config.deauth_interface = others[index - 1]

    config.deauth_enabled = api.confirm(
        f"Send deauth frames from {config.deauth_interface} toward the real AP?",
        default=True,
    )
    if not config.deauth_enabled:
        config.deauth_interface = ""


def _prompt_target_psk(config, api: Any) -> bool:
    import modules.figolab.evil_twin_menu as menu

    if not (
        config.portal_enabled
        and config.portal.require_login
        and config.portal.verify_target_password
    ):
        return True
    menu.console.print(
        Panel(
            "Enter the legitimate corporate Wi-Fi password for this target.\n"
            "Figo compares submissions in memory only — it is never saved to disk or reports.",
            title="Target network verification",
            border_style="yellow",
        )
    )
    try:
        psk = getpass.getpass("Corporate Wi-Fi password (hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        menu.console.print("\n[dim]Assessment cancelled.[/dim]")
        api.pause()
        return False
    if not psk:
        api.warn_and_back(
            "Password required",
            "Verification is enabled but no corporate password was provided.",
        )
        return False
    config.target_verify_psk = psk
    return True


def _run_lab_flow(settings: Any, api: Any, *, mode: str) -> None:
    import modules.figolab.evil_twin_menu as menu

    if not api.ensure_root("evil_twin"):
        return
    if not menu._ensure_lab_tools(api):
        return

    row = menu._pick_target(settings, api)
    if row is None:
        return

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
    menu._show_target_info(row, settings.interface)
    api.pause("Press Enter to configure the lab AP...")

    network = menu._lab_network_from_settings(settings)
    menu.console.print(
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
        menu._configure_lab_network(settings, api)

    config = menu._build_lab_config(settings, row, mode)

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
    menu.console.print(
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
        menu.console.print(
            Panel(
                f"Portal title : {config.portal.portal_title}\n"
                f"Contact      : {config.portal.security_contact or '-'}\n"
                f"Sign-in page : {'Yes (password never stored)' if config.portal.require_login else 'No (prompt only)'}\n"
                f"Verify PSK   : {'Yes' if config.portal.verify_target_password else 'No'}\n"
                f"Portal port  : {config.portal_port} (+ captive :80)",
                title="Awareness portal configuration",
                border_style="cyan",
            )
        )
        if not api.confirm("Use this portal configuration?", default=True):
            _configure_portal(settings, api)
            config = menu._build_lab_config(settings, row, mode)

    if not _prompt_target_psk(config, api):
        return

    _configure_deauth(config, settings, api)

    api.clear_screen()
    if not _confirm_start(config, api):
        menu.console.print("[dim]Assessment cancelled.[/dim]")
        api.pause()
        return

    session = None
    report = None
    try:
        menu.console.print("\n[dim]Starting controlled lab AP...[/dim]")
        session = start_lab_session(config, enable_portal=(mode == "awareness"))
        menu.console.print("[green]Lab AP started.[/green]")
        if session.deauth and session.deauth.active:
            menu.console.print(
                f"[orange3]Deauth active on {config.deauth_interface} "
                f"→ {config.target_bssid}[/orange3]"
            )
        elif config.deauth_enabled:
            menu.console.print(
                f"[orange3]Deauth could not start: "
                f"{session.deauth.last_error if session.deauth else 'unknown'}[/orange3]"
            )
        elif len(wireless_interfaces()) < 2:
            menu.console.print(
                "[orange3]No second adapter — clients may stay on the real corporate AP.[/orange3]"
            )
        if session.portal_active and session.portal:
            menu.console.print(f"[dim]Awareness portal:[/dim] {session.portal.url}")
        api.pause("Press Enter for live dashboard (S or Ctrl+C to stop)...")
        _live_dashboard(session, api)
        if session.stop_requested:
            menu.console.print(
                "\n[yellow]Correct password verified — stopping twin AP and restoring network…[/yellow]"
            )
        report = build_session_report(session)
    except LabError as exc:
        api.warn_and_back("Lab failed", str(exc))
    except api.BackToMenu:
        if session is not None:
            try:
                report = build_session_report(session)
            except Exception:
                report = None
        cleanup_lab_session(session)
        _maybe_save_report(report, api)
        raise
    except KeyboardInterrupt:
        menu.console.print("\n[yellow]Stopping assessment...[/yellow]")
        if session is not None and report is None:
            try:
                report = build_session_report(session)
            except Exception:
                report = None
    finally:
        cleanup_lab_session(session)
        menu.console.print("[green]Cleanup complete. Original network state restore attempted.[/green]")
    _maybe_save_report(report, api)
    api.pause()


def _dashboard_renderable(session) -> Panel:
    import modules.figolab.evil_twin_menu as menu
    from modules.figolab.lab_config import channel_band

    session.refresh_client_count()
    session.ensure_services()
    snap = session.metrics.snapshot()
    security = "WPA2 (secured)" if session.config.is_secured() else "open (insecure)"
    portal_ports = ":80 + :{}".format(session.config.portal_port)
    if session.portal and session.portal.bound_ports:
        portal_ports = " + ".join(f":{p}" for p in session.portal.bound_ports)
    portal_disabled = session.config.lab_mode == "wifi" or not session.portal_active
    deauth_line = "[dim]Deauth: Disabled[/dim]"
    if session.deauth and session.deauth.active:
        deauth_line = f"[orange3]Deauth: Active · {session.deauth.base_iface} · bursts {session.deauth.bursts_sent}[/orange3]"
    elif session.config.deauth_enabled:
        err = session.deauth.last_error if session.deauth else ""
        deauth_line = f"[orange3]Deauth: Failed[/orange3]" + (f" · {err[:30]}" if err else "")
    elif len(wireless_interfaces()) < 2:
        deauth_line = "[orange3]Deauth: Unavailable (need 2nd adapter)[/orange3]"
    all_ok = session.ap_ok() and session.dnsmasq_ok() and (portal_disabled or session.portal_ok())
    body = (
        f"SSID: {session.config.effective_ssid()}\n"
        f"Channel: {session.config.channel}  ·  Band: {channel_band(session.config.channel)}\n"
        f"Security: {security}\n"
        f"Gateway: {session.config.gateway_ip}/{session.config.subnet_prefix}\n"
        f"DHCP: {session.config.dhcp_range_start} – {session.config.dhcp_range_end}\n"
        f"Runtime: {session.runtime_sec()}s\n"
        f"{deauth_line}\n"
        f"{'─' * 42}\n"
        f"{menu._health('AP', session.ap_ok())}   "
        f"{menu._health('DHCP/DNS', session.dnsmasq_ok())}   "
        f"{menu._health('Portal', session.portal_ok(), disabled=portal_disabled)}  ·  {portal_ports}\n"
        f"{'─' * 42}\n"
        f"Connected devices  : {snap['connected_devices']}\n"
        f"Portal visits      : {snap['portal_visits']}\n"
        f"Sign-in submissions: {snap['login_submissions']}\n"
        f"[red]Passwords entered  : {snap['passwords_entered']}[/red]\n"
        f"[red]Correct passwords: {snap.get('correct_passwords', 0)}[/red]  [dim](awareness failure)[/dim]\n"
        f"Wrong passwords    : {snap.get('wrong_passwords', 0)}\n"
        f"Interactions       : {snap['interactions']}\n"
        f"Completed          : {snap['completed']}\n"
        f"{'─' * 42}\n"
        f"[dim]Connected clients (ip · mac · host)[/dim]\n"
        f"{menu._format_clients(session.recent_clients(5))}\n"
        f"{'─' * 42}\n"
        f"[dim]Live behaviour events[/dim]\n"
        f"{menu._format_events(session.metrics.recent_events(6))}"
    )
    return Panel(
        body,
        title="SECURITY AWARENESS LAB",
        subtitle="[S] Stop Assessment  ·  Ctrl+C",
        border_style="green" if all_ok else "yellow",
        box=box.ROUNDED,
    )


def _live_dashboard(session, api: Any) -> None:
    import select
    import sys
    import termios
    import time
    import tty

    import modules.figolab.evil_twin_menu as menu
    from rich.live import Live

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
        with Live(_dashboard_renderable(session), console=menu.console, refresh_per_second=4) as live:
            while not stop:
                if session.stop_requested:
                    stop = True
                    break
                if not session.tracker.alive("hostapd"):
                    menu.console.print("\n[red][ERROR] Lab AP process exited unexpectedly.[/red]")
                    break
                key = _read_key(0.4)
                if key.lower() == "s":
                    stop = True
                    break
                live.update(_dashboard_renderable(session))
    except KeyboardInterrupt:
        pass


def _maybe_save_report(report, api: Any) -> None:
    import modules.figolab.evil_twin_menu as menu
    from modules.exceptions import BackToMenu, ExitApp

    if not report:
        return
    report_data, report_text = report
    metrics = report_data.get("metrics", {})
    menu.console.print(
        Panel(
            f"Connected devices  : {metrics.get('connected_devices', 0)}\n"
            f"Sign-in submissions: {metrics.get('login_submissions', 0)}\n"
            f"Passwords entered  : {metrics.get('passwords_entered', 0)}\n"
            f"Correct passwords: {metrics.get('correct_passwords', 0)} (awareness failure)\n"
            f"Wrong passwords  : {metrics.get('wrong_passwords', 0)}\n"
            f"Completed          : {metrics.get('completed', 0)}",
            title="Session summary (for report)",
            border_style="cyan",
        )
    )
    try:
        if not api.confirm("Save a session report file for the debrief?", default=True):
            return
    except (BackToMenu, ExitApp):
        return
    try:
        path = save_session_report(report_data, report_text)
    except OSError as exc:
        menu.console.print(f"[yellow]Could not save report:[/yellow] {exc}")
        return
    menu.console.print(f"[green]Report saved:[/green] {path}")
    menu.console.print(f"[dim]JSON:[/dim] {path.with_suffix('.json')}")
