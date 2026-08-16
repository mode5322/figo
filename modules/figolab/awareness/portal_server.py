"""Local Security Awareness Portal HTTP server.

Captive-portal behaviour
------------------------
Phones and laptops decide a network "has no internet / needs sign-in" by
probing well-known URLs (Apple ``captive.apple.com``, Android
``connectivitycheck.gstatic.com/generate_204``, Windows ``msftconnecttest``).
dnsmasq resolves every hostname to the lab gateway, so those probes reach this
server. To make the sign-in page pop up automatically we:

* listen on **port 80** (where the OS probes go) in addition to the configured
  portal port, and
* answer *every* request with the portal page (instead of the "Success" body
  the OS expects), which triggers the captive-portal assistant on the client.

Credential safety
-----------------
The sign-in form posts to ``/login``. The submitted password is read only to
compute a single boolean (was the field non-empty?) and is then discarded. It
is never stored, logged, hashed, or transmitted anywhere.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qs

from modules.figolab.awareness import portal_pages as templates
from modules.figolab.awareness.awareness_metrics import MetricsStore, safe_record_interaction
from modules.figolab.awareness.client_sessions import SessionStore

if TYPE_CHECKING:
    from modules.figolab.lab_config import LabConfig

# Standard port used by OS captive-portal probes.
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
        """True if the portal is active and at least one server thread is running."""
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

    def _result_body(self, client_session) -> str:
        """
        Realistic post–sign-in confirmation shown to the participant.

        The educational reveal is intentionally NOT shown here — it is delivered
        later during the debrief / manual report using the live dashboard
        screenshots and the configured ``educational_message``. On-screen the
        participant only sees an ordinary "connected" page.
        """
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
                path = self.path.split("?", 1)[0]
                if path.startswith("/health"):
                    self._send(200, "ok", session.session_id, "text/plain; charset=utf-8")
                    return
                portal.metrics.mark_portal_opened(session.session_id)
                session.portal_opened = True
                if path.startswith("/result"):
                    portal.metrics.mark_completed(session.session_id)
                    session.completed = True
                    self._send(200, portal._result_body(session), session.session_id)
                    return
                # Every other path (including OS captive-portal probes) serves the
                # sign-in / landing page so the assistant opens on the client.
                self._send(200, portal._landing_body(session), session.session_id)

            def do_POST(self) -> None:  # noqa: N802
                session = self._session()
                path = self.path.split("?", 1)[0]
                length = int(self.headers.get("Content-Length", "0") or 0)
                # Cap body size; never log raw body.
                length = min(max(length, 0), 4096)
                raw = self.rfile.read(length) if length else b""
                form = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)

                if path.startswith("/login"):
                    # Read the password field ONLY to compute a boolean, then drop it.
                    password = form.get("password", [""])[0]
                    entered_password = bool((password or "").strip())
                    password = None  # noqa: F841 — explicit discard
                    form.pop("password", None)
                    form.pop("username", None)
                    portal.metrics.mark_login_submitted(session.session_id, entered_password)
                    session.submitted_login = True
                    session.entered_password = entered_password
                    session.security_prompt_interaction = True
                    portal.metrics.mark_completed(session.session_id)
                    session.completed = True
                    self._send(200, portal._result_body(session), session.session_id)
                    return

                # Legacy behavioural buttons (used when require_login is disabled).
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
                    training_input = None
                else:
                    safe_record_interaction(portal.metrics, session.session_id)
                    session.security_prompt_interaction = True

                portal.metrics.mark_completed(session.session_id)
                session.completed = True
                self._send(200, portal._result_body(session), session.session_id)

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
                # e.g. port 80 already taken; keep trying the remaining ports.
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
