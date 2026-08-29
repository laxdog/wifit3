"""Captive-portal HTTP server: minimal GET/POST handling, scoped to the TAP interface. Before a
client submits the form, every path except the portal root 302-redirects there -- enough to
trigger the captive-portal flow on iOS/Android/Windows alike, since none of them will see the
exact "you have real internet" response they're each individually checking for. GET / serves the
portal page; a POST or a GET to the real portal's own submit/continue link (nodogsplash and
openNDS both use method="get" forms, not POST) captures whatever was submitted and marks that
client authorized. A GET to a path referenced by the page itself (its own <img>/<link>/<script>
assets) is served from ``assets`` instead, or 404s if fetching it failed -- neither counts as a
submission, or the page's own incidental resource loads would auto-authorize the client before
they ever saw or clicked anything.

An authorized client is a different story: each OS keeps re-polling its own well-known
detection URL in the background (Apple's hotspot-detect.html, Android's generate_204, Windows'
connecttest.txt/ncsi.txt, Firefox's success.txt -- all resolve here too, via the wildcard DNS) to
decide when to auto-dismiss its sign-in sheet. Answering those correctly once authorized is what
makes that happen instead of leaving the user stuck looking "signed in" but still walled off.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

from wifit3.net.portal_assets import extract_asset_refs
from wifit3.net.tap import SETCAP_HINT, TapPermissionError

logger = logging.getLogger(__name__)

_PORT = 80
_MAX_BODY = 8192
_READ_TIMEOUT = 5

_SUCCESS_PAGE = ('<!doctype html><html><head><meta charset="utf-8"><title>Connected</title></head>'
                 '<body style="font-family:sans-serif;text-align:center;padding-top:3em">'
                 "<h2>You're connected</h2></body></html>")

# path -> (status, content-type, body) each OS's background connectivity check expects once
# there's real internet; served verbatim only to already-authorized clients so the OS notices and
# auto-dismisses its captive-portal sign-in UI.
_APPLE_SUCCESS = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
_CAPTIVE_CHECK_RESPONSES: dict[str, tuple[int, str, str]] = {
    "/hotspot-detect.html": (200, "text/html", _APPLE_SUCCESS),
    "/library/test/success.html": (200, "text/html", _APPLE_SUCCESS),
    "/generate_204": (204, "text/html", ""),
    "/gen_204": (204, "text/html", ""),
    "/connecttest.txt": (200, "text/plain", "Microsoft Connect Test"),
    "/ncsi.txt": (200, "text/plain", "Microsoft NCSI"),
    "/success.txt": (200, "text/plain", "success\n"),
}
_STATUS_REASON = {200: "OK", 204: "No Content", 404: "Not Found"}

# Requested by real browsers on every navigation regardless of whether the page declares one --
# unlike a page's own <link>/<img>/<script> refs (_asset_refs), this isn't something the fetched
# page's HTML ever lists, so it would otherwise fall to the catch-all "this is the real portal's
# own submit link" branch and silently pre-authorize the client before they see the form.
_BROWSER_AUTO_PATHS = frozenset({"/favicon.ico"})

# Apple's CNA sheet reacts to its OWN webview navigating to hotspot-detect.html and seeing the
# exact expected body -- it closes itself right then, rather than waiting out its own background
# recheck timer. Redirecting the POST response there (only for CNA's own browser, identified by
# its distinctive UA, so a normal browser still gets a real "connected" page) is what makes
# sign-in feel instant on iOS/macOS instead of leaving the sheet open for up to a minute.
_APPLE_CNA_UA_MARKER = "captivenetworksupport"


class HttpPortalServer:
    def __init__(self, tap_name: str, *, page: str, on_submit: Optional[Callable[[dict], None]] = None,
                authorized: Optional[Set[str]] = None,
                assets: Optional[Dict[str, Tuple[str, bytes]]] = None):
        self.tap_name = tap_name
        self.page = page
        self.on_submit = on_submit or (lambda _fields: None)
        self.submissions: List[dict] = []
        # source IPs that have already submitted the form; shared with DnsServer when given, so
        # DNS can stop wildcard-hijacking (and start forwarding for real) the moment HTTP does.
        self._authorized: Set[str] = authorized if authorized is not None else set()
        # path -> (content-type, body) for the page's own successfully-fetched local assets
        # (icons/css/images); asset_refs also covers ones referenced but NOT in here (fetch
        # failed) -- those 404 rather than being treated as a submission or looping to "/".
        self._assets: Dict[str, Tuple[str, bytes]] = assets or {}
        self._asset_refs: Set[str] = set(self._assets) | extract_asset_refs(page)
        self._server = None

    async def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            self.tap_name.encode("ascii") + b"\x00")
            sock.bind(("0.0.0.0", _PORT))                 # <1024: needs CAP_NET_BIND_SERVICE too
        except PermissionError as exc:
            sock.close()
            raise TapPermissionError(SETCAP_HINT) from exc
        except OSError:
            sock.close()
            raise
        sock.listen(16)
        self._server = await asyncio.start_server(self._handle, sock=sock)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else None
        try:
            method, path = await self._read_request_line(reader)
            if method is None:
                return
            headers = await self._read_headers(reader)
            body = await self._read_body(reader, headers)
            path_only = urlsplit(path).path
            if method == "POST":
                fields = dict(parse_qsl(body.decode("utf-8", "ignore")))
                await self._authorize_and_respond(writer, headers, client_ip, fields)
            elif path_only in self._asset_refs:
                await self._respond_asset(writer, path_only)
            elif client_ip in self._authorized:
                await self._handle_authorized(writer, path_only)
            elif path_only == "/":
                await self._respond(writer, 200, self.page)
            elif path_only in _CAPTIVE_CHECK_RESPONSES:
                await self._redirect(writer, "/")
            elif path_only in _BROWSER_AUTO_PATHS:
                await self._respond_raw(writer, 404, "text/plain", "Not Found")
            else:
                # Not "/", not a known OS background check, not a page asset: this is the real
                # portal's own submit/continue link -- nodogsplash and openNDS both use
                # method="get" forms, so the submitted fields are in the query string, not a body.
                fields = dict(parse_qsl(urlsplit(path).query))
                await self._authorize_and_respond(writer, headers, client_ip, fields)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def _authorize_and_respond(self, writer: asyncio.StreamWriter, headers: dict,
                                     client_ip: Optional[str], fields: dict) -> None:
        self.submissions.append(fields)
        self.on_submit(fields)
        if client_ip is not None:
            self._authorized.add(client_ip)
        if _APPLE_CNA_UA_MARKER in headers.get("user-agent", "").lower():
            await self._redirect(writer, "/hotspot-detect.html")
        else:
            await self._respond(writer, 200, _SUCCESS_PAGE)

    async def _respond_asset(self, writer: asyncio.StreamWriter, path: str) -> None:
        asset = self._assets.get(path)
        if asset is None:
            await self._respond_raw(writer, 404, "text/plain", "Not Found")
        else:
            content_type, data = asset
            await self._respond_bytes(writer, 200, content_type, data)

    async def _handle_authorized(self, writer: asyncio.StreamWriter, path: str) -> None:
        """Already signed in: answer each OS's own connectivity-check path with what it expects
        to see when there's real internet, so it stops showing the sign-in sheet on its own."""
        check = _CAPTIVE_CHECK_RESPONSES.get(path)
        if check is not None:
            status, content_type, text = check
            await self._respond_raw(writer, status, content_type, text)
        else:
            await self._respond(writer, 200, _SUCCESS_PAGE)

    async def _read_request_line(self, reader: asyncio.StreamReader):
        line = await asyncio.wait_for(reader.readline(), _READ_TIMEOUT)
        if not line:
            return None, None
        parts = line.decode("latin-1", "ignore").split()
        if len(parts) < 2:
            return None, None
        return parts[0], parts[1]

    async def _read_headers(self, reader: asyncio.StreamReader) -> dict:
        headers: dict = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), _READ_TIMEOUT)
            if line in (b"\r\n", b"", b"\n"):
                break
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
        return headers

    async def _read_body(self, reader: asyncio.StreamReader, headers: dict) -> bytes:
        length = min(int(headers.get("content-length", "0") or "0"), _MAX_BODY)
        if length <= 0:
            return b""
        return await asyncio.wait_for(reader.readexactly(length), _READ_TIMEOUT)

    async def _respond(self, writer: asyncio.StreamWriter, status: int, body: str) -> None:
        await self._respond_raw(writer, status, "text/html; charset=utf-8", body)

    async def _respond_raw(self, writer: asyncio.StreamWriter, status: int, content_type: str,
                           body: str) -> None:
        await self._respond_bytes(writer, status, content_type, body.encode("utf-8"))

    async def _respond_bytes(self, writer: asyncio.StreamWriter, status: int, content_type: str,
                             data: bytes) -> None:
        reason = _STATUS_REASON.get(status, "OK")
        writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n"
                     f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode("ascii") + data)
        await writer.drain()

    async def _redirect(self, writer: asyncio.StreamWriter, location: str) -> None:
        writer.write(f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n"
                     f"Connection: close\r\n\r\n".encode("ascii"))
        await writer.drain()
