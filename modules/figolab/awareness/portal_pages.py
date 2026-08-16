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
  </div>
</body>
</html>
"""


def login_page(
    *,
    ssid: str,
    title: str,
    organization: str,
    username_label: str = "Username / Email",
    password_label: str = "Wi-Fi / Network password",
    button_label: str = "Sign in",
) -> str:
    """Realistic Wi-Fi/network sign-in page. Form posts to /login."""
    org = f"<p class='muted'>{_e(organization)}</p>" if organization else ""
    heading = _e(organization or title)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{_e(title)}</title>
  <style>
    :root {{
      --bg:#0f1419; --card:#1a222c; --text:#e8eef5; --muted:#9aa7b5;
      --accent:#3d8bfd; --line:#2b3642; --field:#111820;
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0; min-height:100vh; display:grid; place-items:center;
      font-family:"Segoe UI",system-ui,sans-serif;
      background:radial-gradient(circle at top,#1c2733,var(--bg)); color:var(--text);
    }}
    .card {{
      width:min(400px,92vw); background:var(--card); border:1px solid var(--line);
      border-radius:14px; padding:28px 24px; box-shadow:0 20px 50px rgba(0,0,0,.35);
    }}
    .brand {{ display:flex; align-items:center; gap:10px; margin-bottom:6px; }}
    .brand .lock {{ color:#3dd68c; font-size:1.1rem; }}
    h1 {{ margin:0; font-size:1.15rem; }}
    .ssid {{
      margin:14px 0 18px; padding:12px; text-align:center; font-weight:700;
      border:1px dashed #3a4756; border-radius:10px; color:#f0b429;
    }}
    label {{ display:block; font-size:.85rem; color:var(--muted); margin:12px 0 6px; }}
    input {{
      width:100%; padding:11px 12px; border-radius:9px; border:1px solid var(--line);
      background:var(--field); color:var(--text); font-size:1rem;
    }}
    button {{
      width:100%; margin-top:18px; border:0; border-radius:10px; padding:12px 14px;
      background:var(--accent); color:#fff; font-weight:600; font-size:1rem; cursor:pointer;
    }}
    .muted {{ color:var(--muted); font-size:.88rem; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="brand"><span class="lock">&#128274;</span><h1>{heading}</h1></div>
    {org}
    <p class="muted">Sign in to access the network:</p>
    <div class="ssid">{_e(ssid)}</div>
    <form method="post" action="/login" autocomplete="off">
      <label for="u">{_e(username_label)}</label>
      <input id="u" name="username" autocomplete="off"/>
      <label for="p">{_e(password_label)}</label>
      <input id="p" name="password" type="password" autocomplete="off"/>
      <button type="submit">{_e(button_label)}</button>
    </form>
  </div>
</body>
</html>
"""


def connected_page(*, ssid: str, title: str, organization: str) -> str:
    """Captive-portal connected confirmation shown after sign-in."""
    org = f"<p class='muted'>{_e(organization)}</p>" if organization else ""
    net = f"<div class='ssid'>{_e(ssid)}</div>" if ssid else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{_e(title)}</title>
  <style>
    * {{ box-sizing:border-box; }}
    body {{
      margin:0; min-height:100vh; display:grid; place-items:center;
      font-family:"Segoe UI",system-ui,sans-serif;
      background:radial-gradient(circle at top,#1c2733,#0f1419); color:#e8eef5;
    }}
    .card {{
      width:min(400px,92vw); background:#1a222c; border:1px solid #2b3642;
      border-radius:14px; padding:32px 24px; text-align:center;
      box-shadow:0 20px 50px rgba(0,0,0,.35);
    }}
    .check {{
      width:64px; height:64px; margin:0 auto 14px; border-radius:50%;
      background:#123524; display:grid; place-items:center;
      color:#3dd68c; font-size:2rem; border:1px solid #1f5a3c;
    }}
    h1 {{ margin:0 0 6px; font-size:1.2rem; }}
    p {{ line-height:1.5; }}
    .muted {{ color:#9aa7b5; font-size:.92rem; }}
    .ssid {{
      margin:16px 0 4px; padding:12px; font-weight:700; color:#f0b429;
      border:1px dashed #3a4756; border-radius:10px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="check">&#10003;</div>
    <h1>You are connected</h1>
    {org}
    <p class="muted">Your device now has network access.</p>
    {net}
    <p class="muted">You can return to your browser and continue.</p>
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
<p class="muted">Interaction only.</p>
{field}
<form method="get" action="/result"><button type="submit">Show result</button></form>
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
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_e(title)}</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Segoe UI,system-ui,sans-serif;background:#0f1419;color:#e8eef5}}
.card{{width:min(560px,92vw);background:#1a222c;border:1px solid #2b3642;border-radius:14px;padding:28px 24px;line-height:1.55}}
h1{{margin-top:0;font-size:1.2rem}} .ok{{color:#3dd68c}}
.behaviors{{margin:14px 0;padding:12px 14px;border-radius:10px;background:#111820;border:1px solid #2b3642}}
.behaviors .bh{{margin:0 0 6px;color:#9aa7b5;font-size:.9rem}}
.behaviors ul{{margin:0;padding-left:20px}} .behaviors li{{margin:3px 0}}
</style></head><body><div class="card">
<h1>{_e(title)}</h1>
{org}
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
        "title": getattr(portal, "portal_title", "Wi-Fi Authentication") if portal else "Wi-Fi Authentication",
        "organization": getattr(portal, "organization", "") if portal else "",
        "training_message": getattr(portal, "training_message", "") if portal else "",
        "contact": getattr(portal, "security_contact", "") if portal else "",
        "educational_message": getattr(portal, "educational_message", "") if portal else "",
        "require_login": bool(getattr(portal, "require_login", True)) if portal else True,
        "username_label": getattr(portal, "login_username_label", "Username / Email")
        if portal
        else "Username / Email",
        "password_label": getattr(portal, "login_password_label", "Wi-Fi / Network password")
        if portal
        else "Wi-Fi / Network password",
        "button_label": getattr(portal, "login_button_label", "Sign in") if portal else "Sign in",
    }
