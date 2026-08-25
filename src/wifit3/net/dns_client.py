"""One-shot DNS A-record resolver: used by the real-portal fetch to resolve a hostname-based
captive-portal redirect (``Location: http://guest.example.com/login``) against the target
network's own DNS server. The OS resolver can't be used here -- it isn't scoped to the fetch TAP
and would leak the query out the host's real uplink instead of over the association being tested.
"""
from __future__ import annotations

import asyncio
import os
import socket
import struct
from typing import Optional

_PORT = 53
_DEFAULT_TIMEOUT = 3.0
_TYPE_A, _CLASS_IN = 1, 1


def build_query(hostname: str, qid: bytes) -> bytes:
    header = qid + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in hostname.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", _TYPE_A, _CLASS_IN)
    return header + question


def parse_a_answer(packet: bytes, qid: bytes) -> Optional[str]:
    """First A record in a reply matching ``qid``, or None (no answer, wrong id, malformed)."""
    if len(packet) < 12 or packet[0:2] != qid:
        return None
    qdcount, ancount = struct.unpack_from("!HH", packet, 4)
    i = 12
    for _ in range(qdcount):
        i = _skip_name(packet, i)
        if i is None:
            return None
        i += 4                                           # qtype + qclass
    for _ in range(ancount):
        i = _skip_name(packet, i)
        if i is None or i + 10 > len(packet):
            return None
        rtype, _rclass, _ttl, rdlength = struct.unpack_from("!HHIH", packet, i)
        i += 10
        if i + rdlength > len(packet):
            return None
        if rtype == _TYPE_A and rdlength == 4:
            return ".".join(str(b) for b in packet[i:i + 4])
        i += rdlength
    return None


def _skip_name(packet: bytes, i: int) -> Optional[int]:
    if i >= len(packet):
        return None
    if packet[i] & 0xC0 == 0xC0:                          # compressed name: one pointer, done
        return i + 2 if i + 2 <= len(packet) else None
    while i < len(packet) and packet[i] != 0:
        i += packet[i] + 1
    return i + 1 if i < len(packet) else None


async def resolve(tap_name: str, dns_ip: str, hostname: str, *,
                  timeout: float = _DEFAULT_TIMEOUT) -> Optional[str]:
    """A-record lookup for ``hostname`` against ``dns_ip``, scoped to ``tap_name``. None on any
    failure (no answer, timeout, no route): always best-effort, never raises."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, tap_name.encode("ascii") + b"\x00")
        sock.setblocking(False)
        qid = os.urandom(2)
        loop = asyncio.get_running_loop()
        await loop.sock_sendto(sock, build_query(hostname, qid), (dns_ip, _PORT))
        data = await asyncio.wait_for(loop.sock_recv(sock, 512), timeout)
        return parse_a_answer(data, qid)
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        sock.close()
