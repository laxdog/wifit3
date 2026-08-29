"""Minimal DHCP server (DISCOVER/OFFER/REQUEST/ACK only) for the small subnet behind a
``TapDevice``. Protocol encode/parse is pure and unit-testable; ``DhcpServer`` is the thin
socket loop around it, scoped to just the TAP interface (``SO_BINDTODEVICE``) so it can never
answer real DHCP traffic on the host's other interfaces.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Dict, Optional

from wifit3.net.tap import SETCAP_HINT, TapPermissionError

logger = logging.getLogger(__name__)

_SERVER_PORT = 67
_CLIENT_PORT = 68
_MAGIC_COOKIE = bytes.fromhex("63825363")
_OP_REQUEST, _OP_REPLY = 1, 2
_HTYPE_ETHERNET = 1
_BOOTP_HEADER_LEN = 240   # up to and including the magic cookie; options follow

DISCOVER, OFFER, REQUEST, ACK, NAK = 1, 2, 3, 5, 6

_OPT_SUBNET_MASK, _OPT_ROUTER, _OPT_DNS = 1, 3, 6
_OPT_REQUESTED_IP, _OPT_LEASE_TIME = 50, 51
_OPT_MSG_TYPE, _OPT_SERVER_ID = 53, 54
_OPT_END = 255

_LEASE_SECONDS = 3600


@dataclass
class DhcpRequest:
    msg_type: int
    xid: bytes
    chaddr: bytes             # 6-byte client MAC
    requested_ip: Optional[str] = None


def parse(packet: bytes) -> Optional[DhcpRequest]:
    """Decode a client->server BOOTP/DHCP datagram, or None if it isn't one we handle."""
    if len(packet) < _BOOTP_HEADER_LEN or packet[0] != _OP_REQUEST:
        return None
    if packet[236:240] != _MAGIC_COOKIE:
        return None
    xid, chaddr = packet[4:8], packet[28:34]
    msg_type, requested_ip = None, None
    opts, i = packet[_BOOTP_HEADER_LEN:], 0
    while i < len(opts):
        tag = opts[i]
        if tag in (0, _OPT_END):
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        length = opts[i + 1]
        value = opts[i + 2:i + 2 + length]
        if tag == _OPT_MSG_TYPE and length == 1:
            msg_type = value[0]
        elif tag == _OPT_REQUESTED_IP and length == 4:
            requested_ip = ".".join(str(b) for b in value)
        i += 2 + length
    if msg_type is None:
        return None
    return DhcpRequest(msg_type=msg_type, xid=xid, chaddr=chaddr, requested_ip=requested_ip)


def build_reply(*, msg_type: int, xid: bytes, chaddr: bytes, your_ip: str, server_ip: str,
                router_ip: str, dns_ip: str, prefix: int = 24) -> bytes:
    """Encode a server->client BOOTP/DHCP reply (OFFER or ACK)."""
    header = (struct.pack("!BBBB", _OP_REPLY, _HTYPE_ETHERNET, 6, 0) + xid
             + b"\x00\x00\x00\x00"                     # secs + flags
             + b"\x00\x00\x00\x00"                      # ciaddr
             + _ip_bytes(your_ip) + b"\x00\x00\x00\x00"  # yiaddr, siaddr
             + b"\x00\x00\x00\x00"                        # giaddr
             + chaddr + b"\x00" * 10                       # chaddr, padded to 16
             + b"\x00" * 64 + b"\x00" * 128                 # sname, file
             + _MAGIC_COOKIE)
    opts = (_opt(_OPT_MSG_TYPE, bytes([msg_type]))
           + _opt(_OPT_SERVER_ID, _ip_bytes(server_ip))
           + _opt(_OPT_LEASE_TIME, struct.pack("!I", _LEASE_SECONDS))
           + _opt(_OPT_SUBNET_MASK, _ip_bytes(_prefix_to_mask(prefix)))
           + _opt(_OPT_ROUTER, _ip_bytes(router_ip))
           + _opt(_OPT_DNS, _ip_bytes(dns_ip))
           + bytes([_OPT_END]))
    return header + opts


def _opt(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(p) for p in ip.split("."))


def _prefix_to_mask(prefix: int) -> str:
    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ".".join(str((bits >> s) & 0xFF) for s in (24, 16, 8, 0))


def _offset_ip(base: str, n: int) -> str:
    octets = [int(p) for p in base.split(".")]
    octets[3] += n
    return ".".join(str(o) for o in octets)


class DhcpServer:
    """Leases sequential addresses from ``pool_start`` by client MAC (no persistence: fine for
    the lifetime of one EvilTwin run)."""

    def __init__(self, tap_name: str, *, server_ip: str, pool_start: str, prefix: int = 24):
        self.tap_name = tap_name
        self.server_ip = server_ip
        self.pool_start = pool_start
        self.prefix = prefix
        self._leases: Dict[bytes, str] = {}
        self._next = 0
        self._sock: Optional[socket.socket] = None

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            self.tap_name.encode("ascii") + b"\x00")
            sock.bind(("0.0.0.0", _SERVER_PORT))          # <1024: needs CAP_NET_BIND_SERVICE too
        except PermissionError as exc:
            sock.close()
            raise TapPermissionError(SETCAP_HINT) from exc
        except OSError:
            sock.close()
            raise
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
            data, _addr = self._sock.recvfrom(2048)
        except (BlockingIOError, OSError):
            return
        req = parse(data)
        if req is None:
            return
        if req.msg_type == DISCOVER:
            self._reply(req, OFFER)
        elif req.msg_type == REQUEST:
            self._reply(req, ACK)

    def _reply(self, req: DhcpRequest, msg_type: int) -> None:
        ip = self._lease_for(req.chaddr)
        reply = build_reply(msg_type=msg_type, xid=req.xid, chaddr=req.chaddr, your_ip=ip,
                            server_ip=self.server_ip, router_ip=self.server_ip,
                            dns_ip=self.server_ip, prefix=self.prefix)
        self._sock.sendto(reply, ("255.255.255.255", _CLIENT_PORT))

    def _lease_for(self, mac: bytes) -> str:
        if mac not in self._leases:
            self._leases[mac] = _offset_ip(self.pool_start, self._next)
            self._next += 1
        return self._leases[mac]
