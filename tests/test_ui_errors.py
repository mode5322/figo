"""Tests for UI error handling and menu input helpers."""

from __future__ import annotations

import pytest

from modules.exceptions import BackToMenu, ExitApp
from modules.ui import ask, confirm, parse_menu_index, run_action


def test_parse_menu_index():
    assert parse_menu_index("", max_index=5) is None
    assert parse_menu_index("2", max_index=5) == 2
    assert parse_menu_index("6", max_index=5) is None
    assert parse_menu_index("x", max_index=5) is None


def test_ask_eof_returns_to_menu(monkeypatch):
    def _eof(*_args, **_kwargs):
        raise EOFError

    monkeypatch.setattr("modules.ui.Prompt.ask", _eof)
    with pytest.raises(BackToMenu):
        ask("x")


def test_ask_eof_exits_app_when_requested(monkeypatch):
    def _eof(*_args, **_kwargs):
        raise EOFError

    monkeypatch.setattr("modules.ui.Prompt.ask", _eof)
    with pytest.raises(ExitApp):
        ask("x", exit_on_interrupt=True)


def test_confirm_keyboard_interrupt(monkeypatch):
    def _interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("modules.ui.Confirm.ask", _interrupt)
    with pytest.raises(BackToMenu):
        confirm("Continue?")


def test_run_action_swallows_unexpected_errors(monkeypatch):
    reported: list[str] = []

    def boom():
        raise RuntimeError("boom")

    monkeypatch.setattr("modules.ui.report_error", lambda *a, **k: reported.append(a[0]))
    monkeypatch.setattr("modules.ui.pause", lambda *_a, **_k: None)

    assert run_action("Test action", boom) is None
    assert reported == ["Test action"]


def test_run_action_propagates_back_to_menu():
    def back():
        raise BackToMenu

    with pytest.raises(BackToMenu):
        run_action("Test action", back)
