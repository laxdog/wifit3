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
import ssl
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit

from wifit3.net.dns_client import resolve as resolve_dns
from wifit3.net.portal_assets import extract_asset_refs, guess_content_type

logger = logging.getLogger(__name__)

_READ_TIMEOUT = 8.0
_MAX_BODY = 262144
_MAX_REDIRECTS = 3
_REQUEST_PATH = "/"
_DEFAULT_PORTS = {"http": 80, "https": 443}
# Real verification (chain + hostname): this is a one-shot fetch of a real site's content for
# cloning, not a live victim's traffic -- there's no reason to blind ourselves to a bad cert.
_TLS_CONTEXT = ssl.create_default_context()


async def fetch_portal_page(tap_name: str, gateway_ip: str, *, dns_ip: Optional[str] = None,
                            path: str = _REQUEST_PATH,
                            timeout: float = _READ_TIMEOUT) -> Optional[str]:
    """GET ``path`` as text, following redirects (http or https). None on any failure -- always
    best-effort, the caller falls back to a template."""
    data, _host, _port, _scheme = await _fetch_with_redirects(tap_name, gateway_ip, 80, "http",
                                                               path, timeout, dns_ip=dns_ip)
    return data.decode("utf-8", "replace") if data is not None else None


async def fetch_page_with_assets(tap_name: str, gateway_ip: str, *, dns_ip: Optional[str] = None,
                                 path: str = _REQUEST_PATH, timeout: float = _READ_TIMEOUT
                                 ) -> Tuple[Optional[str], Dict[str, Tuple[str, bytes]]]:
    """Like ``fetch_portal_page``, but also best-effort fetches the page's own local asset refs,
    from wherever the page itself landed (its real GatewayPort/scheme), not port 80 (redirects)."""
    data, host, port, scheme = await _fetch_with_redirects(tap_name, gateway_ip, 80, "http",
                                                            path, timeout, dns_ip=dns_ip)
    if data is None:
        return None, {}
    page = data.decode("utf-8", "replace")
    assets: Dict[str, Tuple[str, bytes]] = {}
    for ref in extract_asset_refs(page):
        asset_data, _h, _p, _s = await _fetch_with_redirects(tap_name, host, port, scheme, ref,
                                                              timeout, dns_ip=dns_ip)
        if asset_data is not None:
            assets[ref] = (guess_content_type(ref), asset_data)
        else:
            logger.info("portal_http_client: asset %s not fetched, clone will 404 it", ref)
    return page, assets


async def _fetch_with_redirects(tap_name: str, host: str, port: int, scheme: str, path: str,
                                timeout: float, *, dns_ip: Optional[str] = None
                                ) -> Tuple[Optional[bytes], str, int, str]:
    """GET-with-redirects loop (following the target's own scheme changes, e.g. an http probe
    redirected to an https login page); also returns where the chain landed, so a caller
    fetching more from the same server (page assets) can start there, not back at port 80."""
    for _ in range(_MAX_REDIRECTS):
        status, headers, body = await _get(tap_name, host, port, scheme, path, timeout, dns_ip=dns_ip)
        if status is None:
            logger.info("portal_http_client: %s://%s:%d%s: no response (connect/request failed)",
                       scheme, host, port, path)
            return None, host, port, scheme
        if status in (301, 302, 303, 307, 308) and "location" in headers:
            nxt = urlsplit(headers["location"])
            if nxt.scheme not in ("", "http", "https"):
                logger.info("portal_http_client: %s://%s:%d%s -> %d redirect to %s (not http(s), "
                           "not chasing it)", scheme, host, port, path, status, headers["location"])
                return None, host, port, scheme
            logger.info("portal_http_client: %s://%s:%d%s -> %d redirect to %s",
                       scheme, host, port, path, status, headers["location"])
            host = nxt.hostname or host
            scheme = nxt.scheme or scheme                # protocol-relative //host/path: inherit
            # A splash server commonly redirects to its own non-default listening port
            # (nodogsplash's GatewayPort 2050, a carrier community-WiFi login over 443) --
            # any port is fine as long as we can still speak the scheme; rejecting non-80
            # here at all was the actual bug behind "gateway ... failed" against nodogsplash.
            port = nxt.port or _DEFAULT_PORTS[scheme]
            path = (nxt.path or "/") + (f"?{nxt.query}" if nxt.query else "")
            continue
        if status == 200 and body:
            logger.info("portal_http_client: %s://%s:%d%s -> 200, %d bytes",
                       scheme, host, port, path, len(body))
            return body, host, port, scheme
        logger.info("portal_http_client: %s://%s:%d%s -> %d, body=%d bytes (not usable)",
                   scheme, host, port, path, status, len(body or b""))
        return None, host, port, scheme
    logger.info("portal_http_client: gave up after %d redirects", _MAX_REDIRECTS)
    return None, host, port, scheme


async def _get(tap_name: str, host: str, port: int, scheme: str, path: str, timeout: float, *,
               dns_ip: Optional[str] = None) -> Tuple[Optional[int], dict, Optional[bytes]]:
    """Scoped connect (untested here, same as ``net/tap.py``'s subprocess calls: pure OS
    integration) + the actual request, which ``_request`` below does and IS unit-tested."""
    connect_ip = host if _is_ipv4(host) else await _resolve_host(tap_name, host, dns_ip, timeout)
    if connect_ip is None:
        logger.info("portal_http_client: couldn't resolve %s", host)
        return None, {}, None
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, tap_name.encode("ascii") + b"\x00")
        sock.setblocking(False)
        await asyncio.wait_for(loop.sock_connect(sock, (connect_ip, port)), timeout)
    except asyncio.TimeoutError:
        logger.info("portal_http_client: connect to %s:%d timed out after %.1fs",
                   connect_ip, port, timeout)
        sock.close()
        return None, {}, None
    except OSError as exc:
        logger.info("portal_http_client: connect to %s:%d failed: %s", connect_ip, port, exc)
        sock.close()
        return None, {}, None
    try:
        if scheme == "https":
            # server_hostname is the ORIGINAL hostname (for SNI + cert verification), never
            # connect_ip -- a bare IP wouldn't match the cert's name even if it resolved fine.
            reader, writer = await asyncio.open_connection(
                sock=sock, ssl=_TLS_CONTEXT, server_hostname=host)
        else:
            reader, writer = await asyncio.open_connection(sock=sock)
    except (ssl.SSLError, OSError) as exc:
        logger.info("portal_http_client: TLS handshake to %s:%d failed: %s", connect_ip, port, exc)
        sock.close()
        return None, {}, None
    return await _request(reader, writer, host, port, scheme, path, timeout)


def _is_ipv4(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


async def _resolve_host(tap_name: str, host: str, dns_ip: Optional[str],
                        timeout: float) -> Optional[str]:
    if dns_ip is None:
        return None
    return await resolve_dns(tap_name, dns_ip, host, timeout=timeout)


async def _request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str,
                   port: int, scheme: str, path: str, timeout: float
                   ) -> Tuple[Optional[int], dict, Optional[bytes]]:
    try:
        # A bare IP in Host: on a non-default port is not what a real browser sends (HTTP/1.1
        # requires the port whenever it's non-default for the scheme in use), and nodogsplash's
        # redirect-vs-serve decision reads Host: to tell "this request is for my own splash
        # server" apart from "still an unauthenticated client trying to reach somewhere else" --
        # omitting it here meant nodogsplash never recognized us on the GatewayPort hop, and kept
        # re-wrapping+redirecting forever.
        host_header = host if port == _DEFAULT_PORTS[scheme] else f"{host}:{port}"
        writer.write((f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Mozilla/5.0\r\n"
                     f"Accept: text/html\r\nConnection: close\r\n\r\n").encode("ascii"))
        await writer.drain()
        status, headers = await _read_head(reader, timeout)
        if status is None:
            logger.info("portal_http_client: %s: response had no parseable status line", host)
            return None, {}, None
        body = await _read_body(reader, headers, timeout)
        return status, headers, body
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        logger.info("portal_http_client: %s: request/response failed: %s", host, exc)
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


async def _read_body(reader: asyncio.StreamReader, headers: dict, timeout: float) -> bytes:
    length = headers.get("content-length")
    if length is not None and length.isdigit():
        return await asyncio.wait_for(reader.readexactly(min(int(length), _MAX_BODY)), timeout)
    return await asyncio.wait_for(reader.read(_MAX_BODY), timeout)
