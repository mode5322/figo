"""Offline handshake cracking workflows."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
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

HASHCAT_GPU_ERROR_HINTS = (
    "no opencl",
    "no devices found",
    "no devices found/left",
    "cl_platform_not_found",
    "clgetplatformids",
    "cuinit",
    "cuda sdk",
    "hip runtime",
    "failed to initialize",
    "self-test failed",
    "permission denied",
    "not a valid opencl",
    "backend initialization",
)


@dataclass
class GpuInfo:
    pci_devices: list[str] = field(default_factory=list)
    nvidia_smi: list[str] = field(default_factory=list)
    hashcat_devices: list[dict[str, str]] = field(default_factory=list)
    backend_ok: bool = False
    backend_summary: str = ""
    backend_error: str = ""
    raw_hashcat_i: str = ""


def _pci_gpu_lines() -> list[str]:
    lspci = which_or_none("lspci")
    if not lspci:
        return []
    _code, out = run_cmd([lspci], timeout=10)
    rows: list[str] = []
    for line in out.splitlines():
        low = line.lower()
        if "vga compatible controller" in low or "3d controller" in low or "display controller" in low:
            # Drop leading bus id prefix noise for display: keep full line.
            rows.append(line.strip())
    return rows


def _nvidia_smi_lines() -> list[str]:
    smi = which_or_none("nvidia-smi")
    if not smi:
        return []
    code, out = run_cmd(
        [smi, "--query-gpu=index,name,driver_version,memory.total", "--format=csv,noheader"],
        timeout=12,
    )
    if code == 0 and out.strip():
        return [ln.strip() for ln in out.splitlines() if ln.strip()]
    code, out = run_cmd([smi, "-L"], timeout=12)
    if code == 0 and out.strip():
        return [ln.strip() for ln in out.splitlines() if ln.strip()]
    return []


def parse_hashcat_backend(text: str) -> tuple[bool, list[dict[str, str]], str]:
    """Return (ok, devices, error_or_summary) from `hashcat -I` output."""
    low = (text or "").lower()
    devices: list[dict[str, str]] = []
    current: dict[str, str] = {}

    def flush() -> None:
        nonlocal current
        if current.get("name") or current.get("type"):
            devices.append(current)
        current = {}

    for line in (text or "").splitlines():
        stripped = line.strip()
        if re.match(r"(?:Backend|OpenCL|HIP|CUDA)\s+Device\s+ID\s+#?\d+", stripped, re.I):
            flush()
            continue
        for key, pattern in (
            ("type", r"^Type\.+:\s*(.+)$"),
            ("vendor", r"^Vendor\.+:\s*(.+)$"),
            ("name", r"^Name\.+:\s*(.+)$"),
            ("memory", r"^Memory\.Total\.+:\s*(.+)$"),
        ):
            match = re.match(pattern, stripped, re.I)
            if match:
                current[key] = match.group(1).strip()
                break
    flush()

    # Prefer GPU-type devices; keep others if no GPU listed.
    gpu_only = [d for d in devices if "gpu" in (d.get("type") or "").lower()]
    chosen = gpu_only or devices

    error = ""
    if "no opencl, hip or cuda compatible platform found" in low:
        error = "No OpenCL / HIP / CUDA compatible platform found."
    elif "cl_platform_not_found" in low or "clgetplatformids()" in low:
        error = "OpenCL platforms not found (runtime/driver missing)."
    elif "no devices found" in low:
        error = "hashcat found no usable devices."
    elif "permission denied" in low and "hashcat" in low:
        error = "hashcat could not write its session directory (permission denied)."

    ok = bool(chosen) and not error
    if ok:
        summary = f"{len(chosen)} backend device(s) ready"
    elif error:
        summary = error
    elif text.strip():
        summary = "hashcat backend probe returned no usable GPU devices."
    else:
        summary = "hashcat backend probe produced no output."
    return ok, chosen, summary


def collect_gpu_info() -> GpuInfo:
    info = GpuInfo(pci_devices=_pci_gpu_lines(), nvidia_smi=_nvidia_smi_lines())
    hashcat = which_or_none("hashcat")
    if not hashcat:
        info.backend_summary = "hashcat is not installed."
        info.backend_error = info.backend_summary
        return info
    _code, out = run_cmd([hashcat, "-I"], timeout=25)
    info.raw_hashcat_i = out
    ok, devices, summary = parse_hashcat_backend(out)
    info.backend_ok = ok
    info.hashcat_devices = devices
    info.backend_summary = summary
    if not ok:
        info.backend_error = summary
    return info


def format_gpu_info_block(info: GpuInfo) -> str:
    lines: list[str] = ["[bold]Graphics card / GPU[/bold]"]
    if info.pci_devices:
        lines.append("[dim]PCI[/dim]")
        for row in info.pci_devices:
            lines.append(f"  • {row}")
    else:
        lines.append("[dim]PCI[/dim]  (none detected via lspci)")

    if info.nvidia_smi:
        lines.append("[dim]nvidia-smi[/dim]")
        for row in info.nvidia_smi:
            lines.append(f"  • {row}")
    elif any("nvidia" in r.lower() for r in info.pci_devices):
        lines.append(
            "[dim]nvidia-smi[/dim]  not available — NVIDIA card seen on PCI, "
            "but driver tools are missing"
        )

    if info.hashcat_devices:
        lines.append("[dim]hashcat backends[/dim]")
        for idx, dev in enumerate(info.hashcat_devices, 1):
            name = dev.get("name") or "?"
            vendor = dev.get("vendor") or ""
            dtype = dev.get("type") or "?"
            memory = dev.get("memory") or ""
            detail = f"{dtype}: {name}"
            if vendor:
                detail += f" ({vendor})"
            if memory:
                detail += f" · {memory}"
            lines.append(f"  {idx}. {detail}")
    else:
        status = info.backend_error or info.backend_summary or "no devices"
        color = "green" if info.backend_ok else "yellow"
        lines.append(f"[dim]hashcat backends[/dim]  [{color}]{status}[/{color}]")

    if info.backend_error and info.pci_devices and not info.backend_ok:
        lines.append(
            "\n[yellow]Figo will not install GPU drivers or CUDA/OpenCL runtimes.[/yellow]\n"
            "[dim]If you want hashcat GPU cracking, install drivers yourself outside Figo,\n"
            "or use aircrack-ng (CPU) instead.[/dim]"
        )
    return "\n".join(lines)


def show_gpu_info_panel(info: GpuInfo, *, title: str = "GPU information") -> None:
    style = "green" if info.backend_ok else "yellow"
    console.print(
        Panel(
            format_gpu_info_block(info),
            title=title,
            border_style=style,
            box=box.ROUNDED,
        )
    )


def hashcat_output_indicates_gpu_error(output: str) -> bool:
    low = (output or "").lower()
    return any(hint in low for hint in HASHCAT_GPU_ERROR_HINTS)


def warn_hashcat_gpu(title: str, body: str, info: GpuInfo, *, detail: str = "") -> None:
    parts = [body.rstrip(), "", format_gpu_info_block(info)]
    if detail.strip():
        tail = "\n".join(detail.strip().splitlines()[-12:])
        parts.extend(["", "[dim]hashcat output (tail)[/dim]", f"[dim]{tail}[/dim]"])
    warn_and_back(title, "\n".join(parts))


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


def crack_hashcat(hashfile: Path, wordlist: str) -> tuple[Optional[str], str, bool]:
    """Run hashcat GPU attack. Returns (key, output, is_error)."""
    hashcat = which_or_none("hashcat")
    if not hashcat:
        return None, "hashcat was not found on PATH", True
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
        return None, str(exc), True

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
        return found, output, False
    low = output.lower()
    if "cracked" in low:
        found = read_hashcat_plain(outfile)
        if found:
            return found, output, False
    if proc.returncode not in {0, 1}:
        return None, output or "hashcat exited with an error", True
    if hashcat_output_indicates_gpu_error(output):
        return None, output, True
    if not output and proc.returncode not in {0, 1}:
        return None, "hashcat exited with an error", True
    return None, output, False


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
        console.print("1  aircrack-ng (CPU)  [default]")
        console.print("2  hashcat (GPU)\n")
        console.print(
            "[dim]Figo never installs NVIDIA/AMD GPU drivers. "
            "GPU mode only runs if your host already has a working hashcat backend.[/dim]\n"
        )
        engine = ask("Engine").strip()
        use_hashcat = engine == "2"
        if engine and engine not in {"1", "2"}:
            warn_and_back("Invalid choice", "Enter 1 or 2.")
            return

    if use_hashcat:
        gpu = collect_gpu_info()
        show_gpu_info_panel(gpu, title="hashcat · GPU check (warning only)")

        if not gpu.backend_ok:
            warn_hashcat_gpu(
                "hashcat GPU unavailable",
                "hashcat cannot use a GPU backend on this host right now.\n\n"
                "[bold]Figo will not install GPU drivers.[/bold]\n"
                "Fix OpenCL/CUDA/HIP yourself outside Figo if you need GPU cracking,\n"
                "or continue with aircrack-ng (CPU).",
                gpu,
                detail=gpu.raw_hashcat_i,
            )
            if not confirm("Use aircrack-ng (CPU) instead?", default=True):
                return
            use_hashcat = False
        elif not which_or_none("hcxpcapngtool"):
            console.print(
                "[yellow]hcxpcapngtool is missing (needed to convert .cap to hashcat 22000).[/yellow]\n"
                "Install it from menu [bold]5[/bold] (package only — not GPU drivers), or use CPU now.\n"
            )
            show_gpu_info_panel(gpu, title="hashcat · GPU (ready, conversion blocked)")
            if not confirm("Use aircrack-ng (CPU) instead?", default=True):
                return
            use_hashcat = False
        else:
            console.print("[dim]Converting capture to hashcat 22000...[/dim]")
            hashfile, conv_err = cap_to_hc22000(capfile)
            if not hashfile:
                warn_hashcat_gpu(
                    "Conversion failed",
                    (conv_err or "Could not convert capture to .hc22000.")
                    + "\n\nYou can retry with aircrack-ng (CPU).",
                    gpu,
                )
                if not confirm("Use aircrack-ng (CPU) instead?", default=True):
                    return
                use_hashcat = False
            else:
                console.print(f"[green]Hash file:[/green] {hashfile}\n")
                console.print("[dim]Running hashcat on GPU...[/dim]\n")
                key, out, is_error = crack_hashcat(hashfile, settings.wordlist)
                console.print()
                if is_error:
                    warn_hashcat_gpu(
                        "hashcat (GPU) failed",
                        "hashcat stopped with a GPU/backend error before finishing the wordlist.\n"
                        "Figo will not attempt to install or repair GPU drivers.",
                        collect_gpu_info(),
                        detail=out,
                    )
                    if confirm("Use aircrack-ng (CPU) instead?", default=True):
                        use_hashcat = False
                    else:
                        return
                else:
                    show_crack_result(key, capfile)
                    pause()
                    return

    console.print("[dim]Running aircrack-ng against the wordlist...[/dim]\n")
    key, _out = crack_capture(capfile, bssid, settings.wordlist)
    console.print()
    show_crack_result(key, capfile)
    pause()

