"""Local Security Awareness Portal HTTP server."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qs

from figolab.awareness import templates
from figolab.awareness.metrics import MetricsStore, safe_record_interaction
from figolab.awareness.session import SessionStore

if TYPE_CHECKING:
    from figolab.models import LabConfig


class AwarenessPortal:
    def __init__(self, config: "LabConfig", metrics: MetricsStore, sessions: SessionStore) -> None:
        self.config = config
        self.metrics = metrics
        self.sessions = sessions
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.active = False

    @property
    def url(self) -> str:
        host = self.config.gateway_ip or "127.0.0.1"
        return f"http://{host}:{self.config.portal_port}/"

    def start(self, bind_host: str = "0.0.0.0") -> None:
        if self.active:
            return
        portal = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:  # noqa: A003
                # Avoid logging request bodies / query strings that might contain training input.
                return

            def _session(self):
                cookie = self.headers.get("Cookie", "")
                sid = ""
                for part in cookie.split(";"):
                    part = part.strip()
                    if part.startswith("figo_sid="):
                        sid = part.split("=", 1)[1].strip()
                        break
                session = portal.sessions.get(sid) if sid else None
                if session is None:
                    session = portal.sessions.create()
                return session

            def _set_cookie(self, sid: str) -> None:
                self.send_header(
                    "Set-Cookie",
                    f"figo_sid={sid}; Path=/; HttpOnly; SameSite=Lax",
                )

            def _send(self, code: int, body: str, sid: str, content_type: str = "text/html; charset=utf-8") -> None:
                data = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self._set_cookie(sid)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                session = self._session()
                portal.metrics.mark_portal_opened(session.session_id)
                session.portal_opened = True
                ctx = templates.render_context(portal.config)
                if self.path.startswith("/result"):
                    portal.metrics.mark_completed(session.session_id)
                    session.completed = True
                    body = templates.result_page(
                        title=ctx["title"],
                        organization=ctx["organization"],
                        educational_message=ctx["educational_message"],
                        contact=ctx["contact"],
                    )
                    self._send(200, body, session.session_id)
                    return
                if self.path.startswith("/health"):
                    self._send(200, "ok", session.session_id, "text/plain; charset=utf-8")
                    return
                body = templates.landing_page(
                    ssid=ctx["ssid"],
                    title=ctx["title"],
                    organization=ctx["organization"],
                    training_message=ctx["training_message"],
                    contact=ctx["contact"],
                )
                self._send(200, body, session.session_id)

            def do_POST(self) -> None:  # noqa: N802
                session = self._session()
                length = int(self.headers.get("Content-Length", "0") or 0)
                # Cap body size; never log raw body.
                length = min(max(length, 0), 4096)
                raw = self.rfile.read(length) if length else b""
                form = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
                action = (form.get("action", ["continue"])[0] or "continue").strip()
                training_input = form.get("training_input", [None])[0]

                expected = portal.config.portal.training_value or ""
                if action == "training_value":
                    safe_record_interaction(
                        portal.metrics,
                        session.session_id,
                        submitted_value=training_input,
                        expected_training_value=expected,
                    )
                    # Drop training_input reference immediately.
                    training_input = None
                else:
                    # Behavioral button — no credential field involved.
                    safe_record_interaction(portal.metrics, session.session_id)
                    session.security_prompt_interaction = True

                portal.metrics.mark_completed(session.session_id)
                session.completed = True
                ctx = templates.render_context(portal.config)
                body = templates.result_page(
                    title=ctx["title"],
                    organization=ctx["organization"],
                    educational_message=ctx["educational_message"],
                    contact=ctx["contact"],
                )
                self._send(200, body, session.session_id)

        self._httpd = ThreadingHTTPServer((bind_host, int(self.config.portal_port)), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="figo-awareness-portal", daemon=True)
        self._thread.start()
        self.active = True

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            try:
                self._httpd.server_close()
            except Exception:
                pass
        self._httpd = None
        self._thread = None
        self.active = False
