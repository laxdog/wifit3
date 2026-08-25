"""Fetches whatever captive-portal HTML a real target serves, over a socket scoped
(``SO_BINDTODEVICE``) to the client-role fetch TAP once it has a DHCP lease. Tries the target's
own gateway IP first -- what a captive portal intercepts regardless of the requested Host/path on
networks that host it there. A redirect can land on a hostname rather than a bare IP (common for
cloud-hosted portals): the OS's own resolver can't be used for that lookup (not scoped to this
TAP), so ``dns_ip`` (the lease's own DNS server) is used instead when given.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Optional, Tuple
from urllib.parse import urlsplit

from wifit3.net.dns_client import resolve as resolve_dns

logger = logging.getLogger(__name__)

_READ_TIMEOUT = 8.0
_MAX_BODY = 262144
_MAX_REDIRECTS = 3
_REQUEST_PATH = "/"


async def fetch_portal_page(tap_name: str, gateway_ip: str, *, dns_ip: Optional[str] = None,
                            path: str = _REQUEST_PATH,
                            timeout: float = _READ_TIMEOUT) -> Optional[str]:
    """GET ``path``, following same-port redirects (resolving a hostname target via ``dns_ip``).
    None on any failure -- always best-effort, the caller falls back to a template."""
    host, port = gateway_ip, 80
    for _ in range(_MAX_REDIRECTS):
        status, headers, body = await _get(tap_name, host, port, path, timeout, dns_ip=dns_ip)
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


async def _get(tap_name: str, host: str, port: int, path: str, timeout: float, *,
               dns_ip: Optional[str] = None) -> Tuple[Optional[int], dict, Optional[str]]:
    """Scoped connect (untested here, same as ``net/tap.py``'s subprocess calls: pure OS
    integration) + the actual request, which ``_request`` below does and IS unit-tested."""
    connect_ip = host if _is_ipv4(host) else await _resolve_host(tap_name, host, dns_ip, timeout)
    if connect_ip is None:
        return None, {}, None
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, tap_name.encode("ascii") + b"\x00")
        sock.setblocking(False)
        await asyncio.wait_for(loop.sock_connect(sock, (connect_ip, port)), timeout)
    except (OSError, asyncio.TimeoutError):
        sock.close()
        return None, {}, None
    reader, writer = await asyncio.open_connection(sock=sock)
    return await _request(reader, writer, host, path, timeout)


def _is_ipv4(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


async def _resolve_host(tap_name: str, host: str, dns_ip: Optional[str],
                        timeout: float) -> Optional[str]:
    if dns_ip is None:
        return None
    return await resolve_dns(tap_name, dns_ip, host, timeout=timeout)


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
