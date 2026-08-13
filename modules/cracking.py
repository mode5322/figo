"""Offline handshake cracking workflows."""

from __future__ import annotations

import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.panel import Panel
from rich.table import Table

from modules.capture import format_bytes
from modules.config import Settings
from modules.constants import DEFAULT_HANDSHAKE_DIR
from modules.exceptions import BackToMenu
from modules.tools import require_bins, require_wordlist, run_cmd, which_or_none
from modules.ui import ask, clear_screen, confirm, console, pause, render_banner, warn_and_back


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

