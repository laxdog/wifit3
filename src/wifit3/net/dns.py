"""Wildcard DNS: every A query answers with our own IP, so any hostname (including each OS's
captive-portal-detection probe) resolves to us. AAAA answers NOERROR/no-record so a client
racing A and AAAA (Happy Eyeballs) doesn't wait out an IPv6 timeout before trying IPv4. No
recursion, no other record types, no upstream forwarding: this is a captive network, not a
resolver.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Optional

from wifit3.net.tap import SETCAP_HINT, TapPermissionError

logger = logging.getLogger(__name__)

_PORT = 53
_TYPE_A, _TYPE_AAAA = 1, 28
_CLASS_IN = 1


def _parse_question(packet: bytes) -> Optional[tuple[bytes, int, int]]:
    """(raw wire-format QNAME, QTYPE, QCLASS) from the first question, or None. QNAME is kept
    as raw label bytes (echoed verbatim into the answer via a compression pointer)."""
    if len(packet) < 12 or struct.unpack_from("!H", packet, 4)[0] < 1:
        return None
    i = 12
    start = i
    while i < len(packet) and packet[i] != 0:
        i += packet[i] + 1
    if i >= len(packet) or i + 5 > len(packet):
        return None
    qname_end = i + 1
    qtype, qclass = struct.unpack_from("!HH", packet, qname_end)
    return packet[start:qname_end], qtype, qclass


def build_reply(query: bytes, ip: str) -> Optional[bytes]:
    """A query -> our IP; anything else (AAAA included) -> NOERROR with no answer."""
    parsed = _parse_question(query)
    if parsed is None:
        return None
    qname, qtype, qclass = parsed
    is_a = qtype == _TYPE_A and qclass == _CLASS_IN
    flags = 0x8180                                       # QR=1, RD=1, RA=1, RCODE=0 (NOERROR)
    header = query[0:2] + struct.pack("!HHHHH", flags, 1, 1 if is_a else 0, 0, 0)
    question = qname + struct.pack("!HH", qtype, qclass)
    if not is_a:
        return header + question
    answer = (b"\xc0\x0c" + struct.pack("!HHIH", _TYPE_A, _CLASS_IN, 60, 4)
             + bytes(int(o) for o in ip.split(".")))
    return header + question + answer


class DnsServer:
    """One reply per query, scoped (``SO_BINDTODEVICE``) to just the TAP interface."""

    def __init__(self, tap_name: str, *, answer_ip: str):
        self.tap_name = tap_name
        self.answer_ip = answer_ip
        self._sock: Optional[socket.socket] = None

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            self.tap_name.encode("ascii") + b"\x00")
            sock.bind(("0.0.0.0", _PORT))                 # <1024: needs CAP_NET_BIND_SERVICE too
        except PermissionError as exc:
            sock.close()
            raise TapPermissionError(SETCAP_HINT) from exc
        sock.setblocking(False)
        self._sock = sock
        asyncio.get_running_loop().add_reader(sock.fileno(), self._on_readable)

    def stop(self) -> None:
        if self._sock is None:
            return
        try:
            asyncio.get_running_loop().remove_reader(self._sock.fileno())
        except RuntimeError:
            pass
        self._sock.close()
        self._sock = None

    def _on_readable(self) -> None:
        try:
            data, addr = self._sock.recvfrom(512)
        except (BlockingIOError, OSError):
            return
        reply = build_reply(data, self.answer_ip)
        if reply is None:
            return
        try:
            self._sock.sendto(reply, addr)
        except OSError:
            logger.debug("dns: reply send failed", exc_info=True)
