"""Captive-portal HTTP server: minimal GET/POST handling, scoped to the TAP interface. Every
path except the portal root 302-redirects there, enough to trigger the captive-portal flow on
iOS/Android/Windows alike, with no per-OS detection-endpoint allowlist needed, since none of them
will see the exact "you have real internet" response they're each individually checking for. GET
/ serves the portal page; POST captures whatever the form submitted.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Callable, List, Optional
from urllib.parse import parse_qsl

from wifit3.net.tap import SETCAP_HINT, TapPermissionError

logger = logging.getLogger(__name__)

_PORT = 80
_MAX_BODY = 8192
_READ_TIMEOUT = 5

_SUCCESS_PAGE = ('<!doctype html><html><head><meta charset="utf-8"><title>Connected</title></head>'
                 '<body style="font-family:sans-serif;text-align:center;padding-top:3em">'
                 "<h2>You're connected</h2></body></html>")


class HttpPortalServer:
    def __init__(self, tap_name: str, *, page: str, on_submit: Optional[Callable[[dict], None]] = None):
        self.tap_name = tap_name
        self.page = page
        self.on_submit = on_submit or (lambda _fields: None)
        self.submissions: List[dict] = []
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
        sock.listen(16)
        self._server = await asyncio.start_server(self._handle, sock=sock)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            method, path = await self._read_request_line(reader)
            if method is None:
                return
            headers = await self._read_headers(reader)
            body = await self._read_body(reader, headers)
            if method == "POST":
                fields = dict(parse_qsl(body.decode("utf-8", "ignore")))
                self.submissions.append(fields)
                self.on_submit(fields)
                await self._respond(writer, 200, _SUCCESS_PAGE)
            elif path == "/":
                await self._respond(writer, 200, self.page)
            else:
                await self._redirect(writer, "/")
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

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
        data = body.encode("utf-8")
        writer.write(f"HTTP/1.1 {status} OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                     f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode("ascii") + data)
        await writer.drain()

    async def _redirect(self, writer: asyncio.StreamWriter, location: str) -> None:
        writer.write(f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n"
                     f"Connection: close\r\n\r\n".encode("ascii"))
        await writer.drain()
