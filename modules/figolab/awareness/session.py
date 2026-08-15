"""Client session store for the awareness portal."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


def new_session_id() -> str:
    return secrets.token_urlsafe(16)


@dataclass
class ClientSession:
    session_id: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    portal_opened: bool = False
    viewed_login: bool = False
    submitted_login: bool = False
    entered_password: bool = False
    security_prompt_interaction: bool = False
    training_action: bool = False
    completed: bool = False
    connected: bool = True

    def expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return now >= self.expires_at


class SessionStore:
    def __init__(self, ttl_sec: int = 3600) -> None:
        self.ttl_sec = max(60, int(ttl_sec))
        self._lock = threading.RLock()
        self._sessions: dict[str, ClientSession] = {}

    def create(self) -> ClientSession:
        with self._lock:
            self.purge_expired()
            sid = new_session_id()
            while sid in self._sessions:
                sid = new_session_id()
            now = time.time()
            session = ClientSession(
                session_id=sid,
                created_at=now,
                expires_at=now + self.ttl_sec,
            )
            self._sessions[sid] = session
            return session

    def get(self, session_id: str) -> Optional[ClientSession]:
        with self._lock:
            self.purge_expired()
            session = self._sessions.get(session_id)
            if session is None or session.expired():
                return None
            return session

    def purge_expired(self) -> int:
        with self._lock:
            now = time.time()
            dead = [sid for sid, s in self._sessions.items() if s.expired(now)]
            for sid in dead:
                del self._sessions[sid]
            return len(dead)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def all_active(self) -> list[ClientSession]:
        with self._lock:
            self.purge_expired()
            return list(self._sessions.values())
