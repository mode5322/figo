"""Terminal UI helpers."""

from __future__ import annotations

import traceback
from typing import Callable, Optional, TypeVar

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from modules.exceptions import BackToMenu, ExitApp

console = Console()
T = TypeVar("T")


def _handle_prompt_interrupt(*, exit_on_interrupt: bool) -> None:
    if exit_on_interrupt:
        raise ExitApp from None
    raise BackToMenu from None


def ask(message: str, *, default: str = "", exit_on_interrupt: bool = False) -> str:
    try:
        return Prompt.ask(f"{message}", default=default, show_default=False)
    except (KeyboardInterrupt, EOFError):
        _handle_prompt_interrupt(exit_on_interrupt=exit_on_interrupt)


def confirm(message: str, *, default: bool = False, exit_on_interrupt: bool = False) -> bool:
    try:
        return Confirm.ask(message, default=default)
    except (KeyboardInterrupt, EOFError):
        _handle_prompt_interrupt(exit_on_interrupt=exit_on_interrupt)


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


def report_error(title: str, body: str, *, detail: Optional[str] = None) -> None:
    text = body
    if detail:
        text = f"{body}\n\n[dim]{detail}[/dim]"
    console.print()
    console.print(
        Panel(
            text,
            title=f"[bold red]Error[/bold red] · {title}",
            border_style="red",
            box=box.ROUNDED,
        )
    )
    pause()


def run_action(label: str, action: Callable[..., T], *args, **kwargs) -> Optional[T]:
    """
    Run a menu action and convert unexpected failures into a user-facing panel.

    BackToMenu / ExitApp / KeyboardInterrupt propagate to the caller.
    """
    try:
        return action(*args, **kwargs)
    except (BackToMenu, ExitApp):
        raise
    except KeyboardInterrupt:
        raise BackToMenu from None
    except Exception as exc:
        detail = str(exc).strip() or exc.__class__.__name__
        report_error(
            label,
            "Something went wrong while running this option.\n"
            "You can try again or choose another menu item.",
            detail=detail,
        )
        return None


def clear_screen() -> None:
    try:
        console.clear()
    except Exception:
        # Non-TTY or unsupported terminal — ignore and continue.
        pass


def is_wpa3(security: str) -> bool:
    low = (security or "").lower()
    if "wpa2" in low and "wpa3" not in low and "sae" not in low:
        return False
    return "wpa3" in low or "sae" in low


def menu_value(text: str, set_: bool) -> str:
    if set_ and text:
        return f"[bold green]{text}[/bold green]"
    return "[dim]not set[/dim]"


def render_banner(settings) -> None:  # noqa: ANN001
    return


def parse_menu_index(raw: str, *, max_index: int) -> Optional[int]:
    """Return 1-based index or None when input is empty / invalid."""
    value = (raw or "").strip()
    if not value:
        return None
    if not value.isdigit():
        return None
    index = int(value)
    if not (1 <= index <= max_index):
        return None
    return index
