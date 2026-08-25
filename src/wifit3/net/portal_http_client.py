"""Fetches whatever captive-portal HTML a real target serves, over a socket scoped
(``SO_BINDTODEVICE``) to the client-role fetch TAP once it has a DHCP lease. No DNS needed:
connects directly to the target's own gateway IP on port 80 -- what a captive portal intercepts
regardless of the requested Host/path, and reachable via the plain connected-subnet route DHCP's
address assignment already created, so no default route is needed either.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Optional, Tuple
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_READ_TIMEOUT = 8.0
_MAX_BODY = 262144
_MAX_REDIRECTS = 3
_REQUEST_PATH = "/"


async def fetch_portal_page(tap_name: str, gateway_ip: str, *,
                            timeout: float = _READ_TIMEOUT) -> Optional[str]:
    """GET / from the gateway, following same-port redirects. None if nothing useful comes
    back (no portal, or any failure) -- always best-effort, the caller falls back to a template."""
    host, port, path = gateway_ip, 80, _REQUEST_PATH
    for _ in range(_MAX_REDIRECTS):
        status, headers, body = await _get(tap_name, host, port, path, timeout)
        if status is None:
            return None
        if status in (301, 302, 303, 307, 308) and "location" in headers:
            nxt = urlsplit(headers["location"])
            if nxt.port and nxt.port != 80:      # HTTPS or a non-portal redirect: not chasing it
                return None
            host = nxt.hostname or host
            path = (nxt.path or "/") + (f"?{nxt.query}" if nxt.query else "")
            continue
        return body if status == 200 and body else None
    return None


async def _get(tap_name: str, host: str, port: int, path: str,
               timeout: float) -> Tuple[Optional[int], dict, Optional[str]]:
    """Scoped connect (untested here, same as ``net/tap.py``'s subprocess calls: pure OS
    integration) + the actual request, which ``_request`` below does and IS unit-tested."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, tap_name.encode("ascii") + b"\x00")
        sock.setblocking(False)
        await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout)
    except (OSError, asyncio.TimeoutError):
        sock.close()
        return None, {}, None
    reader, writer = await asyncio.open_connection(sock=sock)
    return await _request(reader, writer, host, path, timeout)


async def _request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str,
                   path: str, timeout: float) -> Tuple[Optional[int], dict, Optional[str]]:
    try:
        writer.write((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
                     f"Accept: text/html\r\nConnection: close\r\n\r\n").encode("ascii"))
        await writer.drain()
        status, headers = await _read_head(reader, timeout)
        if status is None:
            return None, {}, None
        body = await _read_body(reader, headers, timeout)
        return status, headers, body
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        return None, {}, None
    finally:
        writer.close()


async def _read_head(reader: asyncio.StreamReader, timeout: float):
    line = await asyncio.wait_for(reader.readline(), timeout)
    if not line:
        return None, {}
    parts = line.decode("latin-1", "ignore").split(maxsplit=2)
    if len(parts) < 2 or not parts[1].isdigit():
        return None, {}
    headers: dict = {}
    while True:
        hline = await asyncio.wait_for(reader.readline(), timeout)
        if hline in (b"\r\n", b"", b"\n"):
            break
        if b":" in hline:
            k, v = hline.split(b":", 1)
            headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return int(parts[1]), headers


async def _read_body(reader: asyncio.StreamReader, headers: dict, timeout: float) -> str:
    length = headers.get("content-length")
    if length is not None and length.isdigit():
        data = await asyncio.wait_for(reader.readexactly(min(int(length), _MAX_BODY)), timeout)
    else:
        data = await asyncio.wait_for(reader.read(_MAX_BODY), timeout)
    return data.decode("utf-8", "replace")
