"""Terminal UI helpers."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from modules.exceptions import BackToMenu

console = Console()


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

