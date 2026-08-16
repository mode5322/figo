"""HTML templates for the Security Awareness Portal (no credential fields)."""

from __future__ import annotations

import html
from typing import Any


def _e(value: str) -> str:
    return html.escape(value or "", quote=True)


def landing_page(*, ssid: str, title: str, organization: str, training_message: str, contact: str) -> str:
    org = f"<p class='muted'>{_e(organization)}</p>" if organization else ""
    contact_html = (
        f"<p class='muted'>Security contact: {_e(contact)}</p>" if contact else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{_e(title)}</title>
  <style>
    :root {{
      --bg: #0f1419;
      --card: #1a222c;
      --text: #e8eef5;
      --muted: #9aa7b5;
      --accent: #3d8bfd;
      --warn: #f0b429;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(circle at top, #1c2733, var(--bg));
      color: var(--text);
    }}
    .card {{
      width: min(440px, 92vw); background: var(--card); border: 1px solid #2b3642;
      border-radius: 14px; padding: 28px 24px; box-shadow: 0 20px 50px rgba(0,0,0,.35);
    }}
    h1 {{ margin: 0 0 8px; font-size: 1.25rem; letter-spacing: .04em; }}
    .ssid {{
      margin: 18px 0; padding: 14px; text-align: center; font-size: 1.35rem; font-weight: 700;
      border: 1px dashed #3a4756; border-radius: 10px; color: var(--warn);
    }}
    p {{ line-height: 1.5; color: var(--text); }}
    .muted {{ color: var(--muted); font-size: .92rem; }}
    form {{ margin-top: 18px; }}
    button {{
      width: 100%; border: 0; border-radius: 10px; padding: 12px 14px;
      background: var(--accent); color: white; font-weight: 600; font-size: 1rem; cursor: pointer;
    }}
    button.secondary {{
      margin-top: 10px; background: transparent; border: 1px solid #3a4756; color: var(--text);
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{_e(title)}</h1>
    {org}
    <p>You connected to:</p>
    <div class="ssid">{_e(ssid)}</div>
    <p>{_e(training_message)}</p>
    {contact_html}
    <form method="post" action="/interact">
      <input type="hidden" name="action" value="would_enter_password"/>
      <button type="submit">I would enter my password here</button>
    </form>
    <form method="post" action="/interact">
      <input type="hidden" name="action" value="continue"/>
      <button class="secondary" type="submit">Continue</button>
    </form>
    <p class="muted" style="margin-top:16px">
      This portal never asks for or stores your real password.
    </p>
  </div>
</body>
</html>
"""


def login_page(
    *,
    ssid: str,
    title: str,
    organization: str,
    username_label: str = "",  # kept for call-site compat; unused (password-only)
    password_label: str = "Password",
    button_label: str = "Connect",
) -> str:
    """Classic password-only captive-portal sign-in page. Form posts to /login."""
    org_row = (
        f"<tr><td class='lbl'>Organization:</td><td>{_e(organization)}</td></tr>"
        if organization
        else ""
    )
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
    input[type=submit] {{
      min-width: 88px;
      padding: 3px 14px;
      font-family: Tahoma, Verdana, sans-serif;
      font-size: 13px;
      border: 1px solid #003c74;
      background: #ece9d8;
      cursor: pointer;
    }}
    .note {{ color: #555; margin: 0 0 12px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hd">{_e(title)}</div>
    <div class="bd">
      <p class="note">Enter the network password to continue.</p>
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
      </form>
    </div>
  </div>
</body>
</html>
"""


def connected_page(*, ssid: str, title: str, organization: str) -> str:
    """Classic captive-portal connected confirmation shown after sign-in."""
    org = f"<p>Organization: {_e(organization)}</p>" if organization else ""
    net = f"<p>Network: <b>{_e(ssid)}</b></p>" if ssid else ""
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
    .bd {{ padding: 18px 14px; }}
    h1 {{ margin: 0 0 10px; font-size: 16px; font-weight: bold; }}
    p {{ margin: 8px 0; line-height: 1.45; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hd">{_e(title)}</div>
    <div class="bd">
      <h1>You are connected</h1>
      {org}
      {net}
      <p>Your device now has network access.</p>
      <p>You can return to your browser and continue.</p>
    </div>
  </div>
</body>
</html>
"""


def training_page(*, title: str, has_training_value: bool) -> str:
    field = ""
    if has_training_value:
        field = """
    <form method="post" action="/interact">
      <input type="hidden" name="action" value="training_value"/>
      <label class="muted" for="tv">Optional admin training value (fake)</label>
      <input id="tv" name="training_input" autocomplete="off" style="width:100%;margin:8px 0 12px;padding:10px;border-radius:8px;border:1px solid #3a4756;background:#111820;color:#e8eef5"/>
      <button type="submit">Submit training value</button>
    </form>
"""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_e(title)}</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Segoe UI,system-ui,sans-serif;background:#0f1419;color:#e8eef5}}
.card{{width:min(440px,92vw);background:#1a222c;border:1px solid #2b3642;border-radius:14px;padding:28px 24px}}
.muted{{color:#9aa7b5}} button{{width:100%;border:0;border-radius:10px;padding:12px;background:#3d8bfd;color:#fff;font-weight:600}}
</style></head><body><div class="card">
<h1>{_e(title)}</h1>
<p class="muted">No real passwords are collected. Interaction only.</p>
{field}
<form method="get" action="/result"><button type="submit">Show educational result</button></form>
</div></body></html>
"""


def result_page(
    *,
    title: str,
    organization: str,
    educational_message: str,
    contact: str,
    behaviors: Any = None,
    entered_password: bool = False,
) -> str:
    org = f"<p><strong>{_e(organization)}</strong></p>" if organization else ""
    contact_html = f"<p>Contact: {_e(contact)}</p>" if contact else ""
    # Preserve newlines from admin message as <br>
    message = "<br/>".join(_e(line) for line in (educational_message or "").splitlines())

    behavior_html = ""
    if behaviors:
        items = "".join(f"<li>{_e(str(b))}</li>" for b in behaviors)
        behavior_html = (
            "<div class='behaviors'><p class='bh'>What you just did:</p>"
            f"<ul>{items}</ul></div>"
        )
    alert_html = ""
    if entered_password:
        alert_html = (
            "<div class='alert'>&#9888; You entered a password into an unexpected "
            "Wi-Fi sign-in page. In a real attack, that password could have been "
            "stolen.<br/><strong>Your input was NOT stored or transmitted.</strong></div>"
        )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_e(title)}</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Segoe UI,system-ui,sans-serif;background:#0f1419;color:#e8eef5}}
.card{{width:min(560px,92vw);background:#1a222c;border:1px solid #2b3642;border-radius:14px;padding:28px 24px;line-height:1.55}}
h1{{margin-top:0;font-size:1.2rem}} .ok{{color:#3dd68c}}
.alert{{margin:14px 0;padding:12px 14px;border-radius:10px;background:#3a1c1c;border:1px solid #6b2b2b;color:#ffb4b4}}
.behaviors{{margin:14px 0;padding:12px 14px;border-radius:10px;background:#111820;border:1px solid #2b3642}}
.behaviors .bh{{margin:0 0 6px;color:#9aa7b5;font-size:.9rem}}
.behaviors ul{{margin:0;padding-left:20px}} .behaviors li{{margin:3px 0}}
</style></head><body><div class="card">
<h1>{_e(title)}</h1>
{org}
<p class="ok">This was a controlled security-awareness simulation.</p>
{alert_html}
{behavior_html}
<p>{message}</p>
{contact_html}
</div></body></html>
"""


def render_context(config: Any) -> dict[str, Any]:
    portal = getattr(config, "portal", None)
    return {
        "ssid": getattr(config, "effective_ssid", lambda: "")()
        if callable(getattr(config, "effective_ssid", None))
        else getattr(config, "target_ssid", ""),
        "title": getattr(portal, "portal_title", "SECURITY AWARENESS TEST") if portal else "SECURITY AWARENESS TEST",
        "organization": getattr(portal, "organization", "") if portal else "",
        "training_message": getattr(portal, "training_message", "") if portal else "",
        "contact": getattr(portal, "security_contact", "") if portal else "",
        "educational_message": getattr(portal, "educational_message", "") if portal else "",
        "require_login": bool(getattr(portal, "require_login", True)) if portal else True,
        "username_label": getattr(portal, "login_username_label", "Username / Email")
        if portal
        else "Username / Email",
        "password_label": getattr(portal, "login_password_label", "Password")
        if portal
        else "Password",
        "button_label": getattr(portal, "login_button_label", "Connect") if portal else "Connect",
    }
