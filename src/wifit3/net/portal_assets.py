"""Finds the local <img>/<link>/<script> references a cloned captive-portal page needs to look
right (icons, CSS, images) -- shared between the fetch side (what to actually download) and the
serve side (what NOT to treat as a form submission when requested)."""
from __future__ import annotations

import html
import re
from urllib.parse import urlsplit

_ASSET_TAG_RE = re.compile(
    r'<(?:img|script)\b[^>]*?\bsrc=["\']([^"\']+)["\']|<link\b[^>]*?\bhref=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# extension -> Content-Type for the small, closed set of assets a splash page typically needs.
CONTENT_TYPES = {
    ".css": "text/css", ".js": "application/javascript", ".png": "image/png",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".ico": "image/x-icon", ".svg": "image/svg+xml",
}


def extract_asset_refs(html_text: str) -> set[str]:
    """Same-origin (relative, or absolute-but-plain-http) asset paths referenced in ``html_text``.
    Skips https:/data:/protocol-relative refs -- those can't be intercepted or aren't local."""
    refs: set[str] = set()
    for m in _ASSET_TAG_RE.finditer(html_text):
        # openNDS's own template rendering HTML-entity-escapes slashes in attribute values
        # (href="http:&#47;&#47;status.client/...") -- unescape before treating this as a URL,
        # or "//" never gets recognized and the whole thing is misparsed as one bogus path.
        url = html.unescape(m.group(1) or m.group(2) or "")
        if not url or url.startswith(("data:", "https:", "//")):
            continue
        path = urlsplit(url).path if url.startswith("http:") else url
        if path:
            refs.add(path if path.startswith("/") else f"/{path}")
    return refs


def guess_content_type(path: str) -> str:
    for ext, content_type in CONTENT_TYPES.items():
        if path.lower().endswith(ext):
            return content_type
    return "application/octet-stream"
