"""Shared exceptions."""


class BackToMenu(Exception):
    """Ctrl+C or cancel in a submenu returns to the main menu."""


class ExitApp(Exception):
    """User requested exit from the main menu (Ctrl+C / EOF)."""
