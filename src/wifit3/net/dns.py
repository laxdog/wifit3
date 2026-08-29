"""Wildcard DNS for an unauthorized client: every A query answers with our own IP, so any
hostname (including each OS's captive-portal-detection probe) resolves to us and the
captive-portal flow triggers. AAAA answers NOERROR/no-record so a client racing A and AAAA
(Happy Eyeballs) doesn't wait out an IPv6 timeout before trying IPv4.

Once a client is authorized (POSTed the portal form -- ``authorized`` is the same set
HttpPortalServer marks), its queries are instead forwarded to a real upstream resolver and the
reply relayed back verbatim: without this, internet sharing (NAT) is pointless, since every
hostname the client looks up would still resolve back to us regardless of routing.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Optional, Set, Tuple

from wifit3.net.tap import SETCAP_HINT, TapPermissionError

logger = logging.getLogger(__name__)

_PORT = 53
_TYPE_A, _TYPE_AAAA = 1, 28
_CLASS_IN = 1
_FALLBACK_UPSTREAM = "1.1.1.1"   # only used if /etc/resolv.conf has nothing usable
_MAX_PENDING = 256   # bounds a lost-upstream-reply leak over a long session


def system_resolver() -> str:
    """The host's own configured DNS server (first ``nameserver`` in /etc/resolv.conf), or
    ``_FALLBACK_UPSTREAM``: guaranteed reachable, unlike a hardcoded public one."""
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        pass
    return _FALLBACK_UPSTREAM


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
    """One reply per query, scoped (``SO_BINDTODEVICE``) to the TAP -- except an authorized
    client's queries, forwarded via the plain (unscoped) upstream socket instead."""

    def __init__(self, tap_name: str, *, answer_ip: str, authorized: Optional[Set[str]] = None,
                upstream: Optional[str] = None):
        self.tap_name = tap_name
        self.answer_ip = answer_ip
        self.authorized = authorized if authorized is not None else set()
        self.upstream = upstream if upstream is not None else system_resolver()
        self._sock: Optional[socket.socket] = None
        self._upstream_sock: Optional[socket.socket] = None
        # our own synthetic transaction id -> (client's original id, client addr). Two different
        # clients can pick the same 16-bit id; keying on the client's own id (as this used to)
        # let a second client's query silently overwrite the first's pending entry, misrouting
        # whichever reply came back first. Assigning our own id per forward makes collisions
        # structurally impossible instead of merely unlikely.
        self._pending: dict[bytes, Tuple[bytes, Tuple[str, int]]] = {}
        self._next_id = 0

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
        except OSError:
            sock.close()
            raise
        sock.setblocking(False)
        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.setblocking(False)
        self._sock, self._upstream_sock = sock, upstream_sock
        loop = asyncio.get_running_loop()
        loop.add_reader(sock.fileno(), self._on_readable)
        loop.add_reader(upstream_sock.fileno(), self._on_upstream_readable)

    def stop(self) -> None:
        loop = asyncio.get_running_loop()
        for sock in (self._sock, self._upstream_sock):
            if sock is None:
                continue
            try:
                loop.remove_reader(sock.fileno())
            except RuntimeError:
                pass
            sock.close()
        self._sock = self._upstream_sock = None
        self._pending.clear()

    def _on_readable(self) -> None:
        try:
            data, addr = self._sock.recvfrom(512)
        except (BlockingIOError, OSError):
            return
        if addr[0] in self.authorized:
            self._forward(data, addr)
            return
        reply = build_reply(data, self.answer_ip)
        if reply is None:
            return
        try:
            self._sock.sendto(reply, addr)
        except OSError:
            logger.debug("dns: reply send failed", exc_info=True)

    def _forward(self, query: bytes, client_addr: Tuple[str, int]) -> None:
        if len(query) < 2:
            return
        if len(self._pending) >= _MAX_PENDING:
            self._pending.pop(next(iter(self._pending)))     # drop the oldest, bound the growth
        synth_id = struct.pack("!H", self._next_id)
        self._next_id = (self._next_id + 1) % 0x10000
        self._pending[synth_id] = (query[0:2], client_addr)
        try:
            self._upstream_sock.sendto(synth_id + query[2:], (self.upstream, _PORT))
        except OSError:
            logger.debug("dns: upstream forward failed", exc_info=True)

    def _on_upstream_readable(self) -> None:
        try:
            data, _addr = self._upstream_sock.recvfrom(512)
        except (BlockingIOError, OSError):
            return
        pending = self._pending.pop(data[0:2], None) if len(data) >= 2 else None
        if pending is None:
            return
        client_id, client_addr = pending
        try:
            self._sock.sendto(client_id + data[2:], client_addr)
        except OSError:
            logger.debug("dns: reply relay failed", exc_info=True)
