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
    body {{
      margin: 0;
      background: #e8e8e8;
      color: #000;
      font-family: Tahoma, Verdana, sans-serif;
      font-size: 13px;
    }}
    .wrap {{
      width: 420px;
      margin: 48px auto 0;
      border: 1px solid #999;
      background: #fff;
    }}
    .hd {{
      background: #d4d0c8;
      border-bottom: 1px solid #999;
      padding: 8px 12px;
      font-weight: bold;
      font-size: 14px;
    }}
    .bd {{ padding: 16px 14px 18px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ padding: 6px 4px; vertical-align: middle; }}
    td.lbl {{ width: 110px; color: #333; }}
    input[type=password] {{
      width: 100%;
      box-sizing: border-box;
      padding: 3px 4px;
      border: 1px solid #7f9db9;
      font-family: Tahoma, Verdana, sans-serif;
      font-size: 13px;
    }}
    .actions {{ text-align: right; margin-top: 14px; }}
    input[type=submit], button {{
      min-width: 88px;
      padding: 3px 14px;
      font-family: Tahoma, Verdana, sans-serif;
      font-size: 13px;
      border: 1px solid #003c74;
      background: #ece9d8;
      cursor: pointer;
    }}
    .note {{ color: #555; margin: 0 0 12px; }}
    h1 {{ margin: 0 0 10px; font-size: 16px; font-weight: bold; }}
    p {{ margin: 8px 0; line-height: 1.45; }}
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


def landing_page(*, ssid: str, title: str, organization: str, training_message: str, contact: str) -> str:
    """Fallback page when the password sign-in form is disabled."""
    org = f"<p>Organization: {_e(organization)}</p>" if organization else ""
    msg = f"<p>{_e(training_message)}</p>" if training_message else ""
    contact_html = f"<p>Contact: {_e(contact)}</p>" if contact else ""
    body = f"""      {org}
      <p>Network: <b>{_e(ssid)}</b></p>
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
    org_row = (
        f"<tr><td class='lbl'>Organization:</td><td>{_e(organization)}</td></tr>"
        if organization
        else ""
    )
    body = f"""      <p class="note">Enter the network password to continue.</p>
      <form method="post" action="/login" autocomplete="off">
        <table>
          {org_row}
          <tr><td class="lbl">Network:</td><td><b>{_e(ssid)}</b></td></tr>
          <tr>
            <td class="lbl"><label for="p">{_e(password_label)}:</label></td>
            <td><input id="p" name="password" type="password" autocomplete="off" autofocus/></td>
          </tr>
        </table>
        <div class="actions">
          <input type="submit" value="{_e(button_label)}"/>
        </div>
      </form>"""
    return _classic_shell(title=title, body=body)


def connected_page(*, ssid: str, title: str, organization: str) -> str:
    """Classic captive-portal connected confirmation shown after sign-in."""
    org = f"<p>Organization: {_e(organization)}</p>" if organization else ""
    net = f"<p>Network: <b>{_e(ssid)}</b></p>" if ssid else ""
    body = f"""      <h1>You are connected</h1>
      {org}
      {net}
      <p>Your device now has network access.</p>
      <p>You can return to your browser and continue.</p>"""
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
    }
