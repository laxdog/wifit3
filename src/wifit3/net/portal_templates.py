"""Generic captive-portal page templates: the fallback for a target with no real portal to
clone (or when the clone-fetch fails/isn't enabled). Real captive portals aren't all the same
shape -- some want a password, some want an email, some just want a click -- so this covers the
common patterns rather than picking one.
"""
from __future__ import annotations

import enum
from html import escape

_STYLE = ("body{font-family:-apple-system,sans-serif;max-width:22em;margin:3em auto;padding:0 1em}"
         "input{width:100%;padding:.6em;margin:.5em 0;box-sizing:border-box}"
         "button{width:100%;padding:.7em;background:#0071e3;color:#fff;border:0;border-radius:6px}"
         "label{display:block;font-size:.85em;color:#555;margin:.5em 0}")


class PortalTemplate(enum.Enum):
    PASSWORD = "password"          # "enter this network's WiFi password" - gives the PSK directly
    LOGIN = "login"                 # generic hotel/airport-style email + password
    CLICKTHROUGH = "clickthrough"   # nodogsplash-style: agree to terms, no credential required


def _password_fields():
    fields = ('<input type="password" name="password" placeholder="Wi-Fi password" '
             'required autofocus>')
    return fields, "Enter the network password to continue.", "Join"


def _login_fields():
    fields = ('<input type="email" name="email" placeholder="Email address" required autofocus>'
             '<input type="password" name="password" placeholder="Password" required>')
    return fields, "Sign in to connect to the internet.", "Connect"


def _clickthrough_fields():
    fields = ('<input type="email" name="email" placeholder="Email (optional)">'
             '<label><input type="checkbox" name="agree" value="yes" required style="width:auto">'
             ' I agree to the Terms of Service</label>')
    return fields, "Free WiFi is provided as a courtesy. Please review our terms before connecting.", "Connect"


_FIELDS_BY_TEMPLATE = {
    PortalTemplate.PASSWORD: _password_fields,
    PortalTemplate.LOGIN: _login_fields,
    PortalTemplate.CLICKTHROUGH: _clickthrough_fields,
}


def render(template: PortalTemplate, ssid: str) -> str:
    name = escape(ssid)
    fields, prompt, button = _FIELDS_BY_TEMPLATE[template]()
    return (f'<!doctype html><html><head><meta charset="utf-8">'
           f'<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>{name} - Sign in</title><style>{_STYLE}</style></head>'
           f'<body><h2>{name}</h2><p>{prompt}</p>'
           f'<form method="post">{fields}<button type="submit">{button}</button></form>'
           f'</body></html>')
