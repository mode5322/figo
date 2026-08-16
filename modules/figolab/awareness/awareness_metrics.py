"""Non-sensitive awareness metrics."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class SessionMetrics:
    session_id: str
    timestamp: str = field(default_factory=utc_now_iso)
    connected: bool = True
    portal_opened: bool = False
    viewed_login: bool = False
    submitted_login: bool = False
    # True if the participant typed something into the (fake) password field.
    # The value itself is NEVER stored — only this boolean outcome.
    entered_password: bool = False
    security_prompt_interaction: bool = False
    training_action: bool = False
    completed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "cookie",
    "authorization",
    "credential",
    "credentials",
}


def assert_no_sensitive_payload(payload: dict[str, Any]) -> None:
    """Raise ValueError if payload looks like credential storage."""
    lowered = {str(k).lower() for k in payload}
    bad = lowered & SENSITIVE_KEYS
    if bad:
        raise ValueError(f"Refusing to store sensitive keys: {sorted(bad)}")
    for key, value in payload.items():
        if isinstance(value, str) and key.lower() in {"training_value_submitted"}:
            # Never persist submitted training input; only boolean outcomes.
            raise ValueError("Refusing to store submitted training input values")


class MetricsStore:
    """In-memory metrics only — never persists passwords."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_session: dict[str, SessionMetrics] = {}
        self.connected_devices: int = 0
        self.portal_visits: int = 0
        self.interactions: int = 0
        self.login_submissions: int = 0
        self.passwords_entered: int = 0
        self.completed: int = 0
        self.started_at: float = time.time()
        self._events: list[dict[str, str]] = []
        self._prev_connected: int = 0

    def add_event(self, kind: str, message: str) -> None:
        with self._lock:
            self._events.append(
                {
                    "ts": utc_now_iso(),
                    "kind": str(kind)[:40],
                    "message": str(message)[:160],
                }
            )
            # Keep a bounded ring buffer for the live dashboard.
            if len(self._events) > 200:
                self._events = self._events[-200:]

    def recent_events(self, limit: int = 6) -> list[dict[str, str]]:
        with self._lock:
            return list(self._events[-max(1, int(limit)) :])

    def ensure(self, session_id: str) -> SessionMetrics:
        with self._lock:
            if session_id not in self._by_session:
                self._by_session[session_id] = SessionMetrics(session_id=session_id)
            return self._by_session[session_id]

    def get_session(self, session_id: str) -> Optional[SessionMetrics]:
        with self._lock:
            return self._by_session.get(session_id)

    def mark_portal_opened(self, session_id: str) -> SessionMetrics:
        with self._lock:
            m = self.ensure(session_id)
            if not m.portal_opened:
                m.portal_opened = True
                self.portal_visits += 1
                self.add_event("portal", f"Portal opened · session {session_id[:8]}")
            return m

    def mark_login_viewed(self, session_id: str) -> SessionMetrics:
        with self._lock:
            m = self.ensure(session_id)
            if not m.viewed_login:
                m.viewed_login = True
                self.add_event("login", f"Viewed sign-in page · session {session_id[:8]}")
            return m

    def mark_login_submitted(self, session_id: str, entered_password: bool) -> SessionMetrics:
        """
        Record that the participant submitted the sign-in form.

        `entered_password` is a boolean only: whether the (fake) password field
        was non-empty. The submitted value is never received here and is never
        stored anywhere.
        """
        with self._lock:
            m = self.ensure(session_id)
            first = not m.submitted_login
            m.submitted_login = True
            if not m.security_prompt_interaction:
                m.security_prompt_interaction = True
                self.interactions += 1
            if first:
                self.login_submissions += 1
            if entered_password and not m.entered_password:
                m.entered_password = True
                self.passwords_entered += 1
                self.add_event(
                    "risk",
                    f"ENTERED a password on the fake portal (NOT stored) · {session_id[:8]}",
                )
            elif first:
                self.add_event(
                    "login",
                    f"Submitted sign-in without a password · {session_id[:8]}",
                )
            return m

    def mark_interaction(self, session_id: str) -> SessionMetrics:
        with self._lock:
            m = self.ensure(session_id)
            if not m.security_prompt_interaction:
                m.security_prompt_interaction = True
                self.interactions += 1
                self.add_event("interact", f"Security prompt interaction · {session_id[:8]}")
            return m

    def mark_completed(self, session_id: str) -> SessionMetrics:
        with self._lock:
            m = self.ensure(session_id)
            if not m.completed:
                m.completed = True
                self.completed += 1
                self.add_event("complete", f"Session completed · {session_id[:8]}")
            return m

    def set_connected_devices(self, count: int) -> None:
        with self._lock:
            count = max(0, int(count))
            if count > self._prev_connected:
                delta = count - self._prev_connected
                self.add_event(
                    "client",
                    f"+{delta} client(s) · connected devices now {count}",
                )
            elif count < self._prev_connected:
                self.add_event(
                    "client",
                    f"Client left · connected devices now {count}",
                )
            self.connected_devices = count
            self._prev_connected = count

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            payload = {
                "connected_devices": self.connected_devices,
                "portal_visits": self.portal_visits,
                "interactions": self.interactions,
                "login_submissions": self.login_submissions,
                "passwords_entered": self.passwords_entered,
                "completed": self.completed,
                "runtime_sec": int(time.time() - self.started_at),
                "sessions": [m.to_dict() for m in self._by_session.values()],
                "events": list(self._events[-20:]),
            }
            assert_no_sensitive_payload(payload)
            for item in payload["sessions"]:
                assert_no_sensitive_payload(item)
            return payload

    def export_json(self) -> str:
        return json.dumps(self.snapshot(), ensure_ascii=False, indent=2)

    def clear(self) -> None:
        with self._lock:
            self._by_session.clear()
            self.connected_devices = 0
            self.portal_visits = 0
            self.interactions = 0
            self.login_submissions = 0
            self.passwords_entered = 0
            self.completed = 0
            self.started_at = time.time()
            self._events.clear()
            self._prev_connected = 0


def safe_record_interaction(
    metrics: MetricsStore,
    session_id: str,
) -> dict[str, Any]:
    """Record a behavioral interaction without storing submitted values."""
    metrics.mark_interaction(session_id)
    result = {
        "session_id": session_id,
        "security_prompt_interaction": True,
    }
    assert_no_sensitive_payload(result)
    return result
