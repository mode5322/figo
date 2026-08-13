"""Wordlist discovery helpers."""

from __future__ import annotations

from pathlib import Path

from modules.constants import COMMON_WORDLIST_DIRS


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

