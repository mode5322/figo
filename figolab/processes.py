"""Tracked child-process helpers for lab sessions."""

from __future__ import annotations

import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TrackedProcess:
    name: str
    proc: subprocess.Popen
    started_at: float = field(default_factory=time.time)


class ProcessTracker:
    """Track subprocesses started by Figo lab features only."""

    def __init__(self) -> None:
        self._items: list[TrackedProcess] = []

    @property
    def items(self) -> list[TrackedProcess]:
        return list(self._items)

    def track(self, name: str, proc: subprocess.Popen) -> subprocess.Popen:
        self._items.append(TrackedProcess(name=name, proc=proc))
        return proc

    def start(
        self,
        name: str,
        cmd: list[str],
        *,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) -> subprocess.Popen:
        proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr)  # noqa: S603
        return self.track(name, proc)

    def terminate_all(self, *, grace_sec: float = 2.0) -> None:
        # Stop newest first so dependents die before parents when possible.
        for item in reversed(self._items):
            self._terminate_one(item, grace_sec=grace_sec)
        self._items.clear()

    def _terminate_one(self, item: TrackedProcess, *, grace_sec: float) -> None:
        proc = item.proc
        if proc.poll() is not None:
            return
        try:
            proc.send_signal(signal.SIGTERM)
        except OSError:
            return
        deadline = time.time() + grace_sec
        while time.time() < deadline:
            if proc.poll() is not None:
                return
            time.sleep(0.05)
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def alive(self, name: Optional[str] = None) -> bool:
        for item in self._items:
            if name is not None and item.name != name:
                continue
            if item.proc.poll() is None:
                return True
        return False
