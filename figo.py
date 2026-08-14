#!/usr/bin/env python3
"""figo— A terminal-based Wi-Fi security testing toolkit for authorized lab environments."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repository root is importable when launched via absolute path / symlink.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from modules.cli import main  # noqa: E402
from modules.exceptions import ExitApp  # noqa: E402
from modules.ui import console  # noqa: E402


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, ExitApp):
        console.print("\n[dim]Goodbye.[/dim]")
        raise SystemExit(0)
