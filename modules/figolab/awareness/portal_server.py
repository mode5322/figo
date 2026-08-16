"""Local captive-portal HTTP server.

Phones and laptops probe captive URLs; dnsmasq points them at the lab gateway.
This server listens on port 80 plus the configured portal port and answers every
request with the sign-in page so the OS captive assistant opens.

The sign-in form posts to ``/login``. The password field is read only to compute
a boolean (non-empty?) and is then discarded.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from modules.figolab.awareness import portal_pages as templates
from modules.figolab.awareness.awareness_metrics import MetricsStore, safe_record_interaction
from modules.figolab.awareness.client_sessions import SessionStore

if TYPE_CHECKING:
    from modules.figolab.lab_config import LabConfig

CAPTIVE_PORT = 80


class AwarenessPortal:
    def __init__(self, config: "LabConfig", metrics: MetricsStore, sessions: SessionStore) -> None:
        self.config = config
        self.metrics = metrics
        self.sessions = sessions
        self._servers: list[ThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []
        self.bound_ports: list[int] = []
        self.active = False

    def alive(self) -> bool:
        if not self.active:
            return False
        return any(t.is_alive() for t in self._threads) if self._threads else False

    @property
    def url(self) -> str:
        host = self.config.gateway_ip or "127.0.0.1"
        if CAPTIVE_PORT in self.bound_ports:
            return f"http://{host}/"
        port = self.bound_ports[0] if self.bound_ports else self.config.portal_port
        return f"http://{host}:{port}/"

    def _connected_body(self) -> str:
        ctx = templates.render_context(self.config)
        return templates.connected_page(
            ssid=ctx["ssid"],
            title=ctx["title"],
            organization=ctx["organization"],
        )

    def _landing_body(self, session) -> str:
        ctx = templates.render_context(self.config)
        if ctx.get("require_login", True):
            self.metrics.mark_login_viewed(session.session_id)
            session.viewed_login = True
            return templates.login_page(
                ssid=ctx["ssid"],
                title=ctx["title"],
                organization=ctx["organization"],
                password_label=ctx["password_label"],
                button_label=ctx["button_label"],
            )
        return templates.landing_page(
            ssid=ctx["ssid"],
            title=ctx["title"],
            organization=ctx["organization"],
            training_message=ctx["training_message"],
            contact=ctx["contact"],
        )

    def start(self, bind_host: str = "0.0.0.0") -> None:
        if self.active:
            return
        portal = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:  # noqa: A003
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
                path = self.path.split("?", 1)[0]
                if path.startswith("/health"):
                    self._send(200, "ok", session.session_id, "text/plain; charset=utf-8")
                    return
                portal.metrics.mark_portal_opened(session.session_id)
                session.portal_opened = True
                self._send(200, portal._landing_body(session), session.session_id)

            def do_POST(self) -> None:  # noqa: N802
                session = self._session()
                path = self.path.split("?", 1)[0]
                length = int(self.headers.get("Content-Length", "0") or 0)
                length = min(max(length, 0), 4096)
                raw = self.rfile.read(length) if length else b""
                form = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)

                if path.startswith("/login"):
                    password = form.get("password", [""])[0]
                    entered_password = bool((password or "").strip())
                    password = None  # noqa: F841
                    form.pop("password", None)
                    portal.metrics.mark_login_submitted(session.session_id, entered_password)
                    session.submitted_login = True
                    session.entered_password = entered_password
                    session.security_prompt_interaction = True
                    portal.metrics.mark_completed(session.session_id)
                    session.completed = True
                    self._send(200, portal._connected_body(), session.session_id)
                    return

                # Fallback Continue button when password sign-in is disabled.
                safe_record_interaction(portal.metrics, session.session_id)
                session.security_prompt_interaction = True
                portal.metrics.mark_completed(session.session_id)
                session.completed = True
                self._send(200, portal._connected_body(), session.session_id)

        ports: list[int] = [CAPTIVE_PORT]
        try:
            cfg_port = int(self.config.portal_port)
        except (TypeError, ValueError):
            cfg_port = 8080
        if cfg_port != CAPTIVE_PORT:
            ports.append(cfg_port)

        bound: list[int] = []
        for port in ports:
            try:
                httpd = ThreadingHTTPServer((bind_host, port), Handler)
            except OSError:
                continue
            httpd.daemon_threads = True
            thread = threading.Thread(
                target=httpd.serve_forever,
                name=f"figo-awareness-portal-{port}",
                daemon=True,
            )
            thread.start()
            self._servers.append(httpd)
            self._threads.append(thread)
            bound.append(port)

        if not bound:
            raise OSError(f"Could not bind portal on {bind_host} (tried {ports}).")
        self.bound_ports = bound
        self.active = True

    def stop(self) -> None:
        for httpd in self._servers:
            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass
        self._servers = []
        self._threads = []
        self.bound_ports = []
        self.active = False
