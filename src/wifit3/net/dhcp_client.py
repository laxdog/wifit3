"""Minimal one-shot DHCP client (DISCOVER -> OFFER -> REQUEST -> ACK): used by EvilTwin's
client-role portal fetch to get a real IP from a real target AP, the same way any device joining
that network would. Not general-purpose: one lease, no renewal, no persistence. Protocol
encode/parse is pure and unit-testable; ``request_lease`` is the exchange loop around it. No
bound UDP socket: a broadcast reply isn't kernel-delivered to one on an addressless interface
(confirmed live), so replies arrive as decoded Ethernet frames off a queue instead.
"""
from __future__ import annotations

import asyncio
import logging
import os
import struct
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Set

logger = logging.getLogger(__name__)

_SERVER_PORT = 67
_CLIENT_PORT = 68
_MAGIC_COOKIE = bytes.fromhex("63825363")
_OP_REQUEST, _OP_REPLY = 1, 2
_HTYPE_ETHERNET = 1
_BOOTP_HEADER_LEN = 240
_BROADCAST_FLAG = 0x8000       # ask for a broadcast reply: we have no IP to be unicast to yet

DISCOVER, REQUEST = 1, 3
OFFER, ACK, NAK = 2, 5, 6

_OPT_SUBNET_MASK, _OPT_ROUTER, _OPT_DNS = 1, 3, 6
_OPT_REQUESTED_IP, _OPT_LEASE_TIME = 50, 51
_OPT_MSG_TYPE, _OPT_SERVER_ID = 53, 54
_OPT_PARAM_REQUEST_LIST = 55
_OPT_END = 255

_DEFAULT_TIMEOUT = 8.0
_DEFAULT_RETRIES = 3


@dataclass
class DhcpLease:
    ip: str
    prefix: int
    router: Optional[str]
    dns: Optional[str]
    server_id: str


@dataclass
class DhcpReply:
    msg_type: int
    xid: bytes
    yiaddr: str
    options: Dict[int, bytes]


def _opt(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(p) for p in ip.split("."))


def _ip_str(b: bytes) -> str:
    return ".".join(str(x) for x in b[:4])


def _mask_to_prefix(mask: bytes) -> int:
    return bin(int.from_bytes(mask[:4], "big")).count("1")


def _client_packet(mac: bytes, xid: bytes, msg_type: int, *, extra: bytes) -> bytes:
    header = (struct.pack("!BBBB", _OP_REQUEST, _HTYPE_ETHERNET, 6, 0) + xid
             + struct.pack("!HH", 0, _BROADCAST_FLAG)   # secs, flags
             + b"\x00" * 16                               # ciaddr, yiaddr, siaddr, giaddr
             + mac + b"\x00" * 10                          # chaddr, padded to 16
             + b"\x00" * 64 + b"\x00" * 128                 # sname, file
             + _MAGIC_COOKIE)
    opts = (_opt(_OPT_MSG_TYPE, bytes([msg_type])) + extra
           + _opt(_OPT_PARAM_REQUEST_LIST, bytes([_OPT_SUBNET_MASK, _OPT_ROUTER, _OPT_DNS]))
           + bytes([_OPT_END]))
    return header + opts


def build_discover(mac: bytes, xid: bytes) -> bytes:
    return _client_packet(mac, xid, DISCOVER, extra=b"")


def build_request(mac: bytes, xid: bytes, requested_ip: str, server_id: str) -> bytes:
    extra = (_opt(_OPT_REQUESTED_IP, _ip_bytes(requested_ip))
            + _opt(_OPT_SERVER_ID, _ip_bytes(server_id)))
    return _client_packet(mac, xid, REQUEST, extra=extra)


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return (~total) & 0xFFFF


def wrap_ethernet(bootp: bytes, src_mac: bytes) -> bytes:
    """Hand-build the broadcast Ethernet+IP(src=0.0.0.0)+UDP(68->67) frame around ``bootp``."""
    # A normal socket send can't produce src=0.0.0.0 here: confirmed live, with no address on
    # the interface yet, the kernel picks the *default route's* source IP instead (e.g. the
    # host's real wlan0 address) -- no real DHCP server offers a lease against that.
    udp_len = 8 + len(bootp)
    pseudo = bytes(4) + bytes(4) + b"\x00\x11" + struct.pack("!H", udp_len)
    udp_nocsum = struct.pack("!HHHH", _CLIENT_PORT, _SERVER_PORT, udp_len, 0) + bootp
    udp = struct.pack("!HHHH", _CLIENT_PORT, _SERVER_PORT, udp_len,
                      _ip_checksum(pseudo + udp_nocsum)) + bootp
    total_len = 20 + len(udp)
    ip_nocsum = (struct.pack("!BBHHHBB", 0x45, 0, total_len, 0, 0x4000, 64, 17)
                + b"\x00\x00" + bytes(4) + b"\xff\xff\xff\xff")
    ip = (struct.pack("!BBHHHBB", 0x45, 0, total_len, 0, 0x4000, 64, 17)
         + struct.pack("!H", _ip_checksum(ip_nocsum)) + bytes(4) + b"\xff\xff\xff\xff")
    return b"\xff\xff\xff\xff\xff\xff" + src_mac + b"\x08\x00" + ip + udp


def extract_bootp(eth_frame: bytes) -> Optional[bytes]:
    """Pull the BOOTP payload out of a raw Ethernet+IPv4+UDP frame addressed to port 68, or None
    if it isn't one (any other traffic arriving on the link takes this path too)."""
    if len(eth_frame) < 14 or eth_frame[12:14] != b"\x08\x00":
        return None
    ip = eth_frame[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl + 8 or ip[9] != 17:
        return None
    udp = ip[ihl:ihl + 8]
    if struct.unpack("!H", udp[2:4])[0] != _CLIENT_PORT:
        return None
    return ip[ihl + 8:]


def parse_reply(packet: bytes) -> Optional[DhcpReply]:
    """Decode a server->client BOOTP/DHCP datagram, or None if it isn't one we handle."""
    if len(packet) < _BOOTP_HEADER_LEN or packet[0] != _OP_REPLY:
        return None
    if packet[236:240] != _MAGIC_COOKIE:
        return None
    xid, yiaddr = packet[4:8], _ip_str(packet[16:20])
    options: Dict[int, bytes] = {}
    opts, i = packet[_BOOTP_HEADER_LEN:], 0
    while i < len(opts):
        tag = opts[i]
        if tag in (0, _OPT_END):
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        length = opts[i + 1]
        options[tag] = opts[i + 2:i + 2 + length]
        i += 2 + length
    msg_type = options.get(_OPT_MSG_TYPE)
    if not msg_type:
        return None
    return DhcpReply(msg_type=msg_type[0], xid=xid, yiaddr=yiaddr, options=options)


async def request_lease(mac: bytes, send_frame: Callable[[bytes], None],
                        frames: "asyncio.Queue[bytes]", *,
                        timeout: float = _DEFAULT_TIMEOUT,
                        retries: int = _DEFAULT_RETRIES) -> Optional[DhcpLease]:
    """DISCOVER -> OFFER -> REQUEST -> ACK. ``send_frame`` transmits; ``frames`` is fed every
    decoded Ethernet frame arriving on the link (no bound socket: see module docstring)."""
    xid = os.urandom(4)
    offer = await _exchange(frames, wrap_ethernet(build_discover(mac, xid), mac),
                            xid, {OFFER}, timeout, retries, send_frame)
    if offer is None:
        return None
    server_id_bytes = offer.options.get(_OPT_SERVER_ID)
    if not server_id_bytes:
        return None
    server_id = _ip_str(server_id_bytes)
    req = wrap_ethernet(build_request(mac, xid, offer.yiaddr, server_id), mac)
    ack = await _exchange(frames, req, xid, {ACK}, timeout, retries, send_frame)
    if ack is None:
        return None
    mask, router, dns = (ack.options.get(_OPT_SUBNET_MASK), ack.options.get(_OPT_ROUTER),
                         ack.options.get(_OPT_DNS))
    return DhcpLease(ip=ack.yiaddr, prefix=_mask_to_prefix(mask) if mask else 24,
                     router=_ip_str(router) if router else None,
                     dns=_ip_str(dns) if dns else None, server_id=server_id)


async def _exchange(frames: "asyncio.Queue[bytes]", frame: bytes, xid: bytes,
                    want_types: Set[int], timeout: float, retries: int,
                    send_frame: Callable[[bytes], None]) -> Optional[DhcpReply]:
    per_try = timeout / max(retries, 1)
    for _ in range(retries):
        send_frame(frame)
        reply = await _wait_for_reply(frames, xid, want_types, per_try)
        if reply is not None:
            return reply
    return None


async def _wait_for_reply(frames: "asyncio.Queue[bytes]", xid: bytes, want_types: Set[int],
                          timeout: float) -> Optional[DhcpReply]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return None
        try:
            eth_frame = await asyncio.wait_for(frames.get(), remaining)
        except asyncio.TimeoutError:
            return None
        bootp = extract_bootp(eth_frame)
        if bootp is None:
            continue
        reply = parse_reply(bootp)
        if reply is not None and reply.xid == xid and reply.msg_type in want_types:
            return reply
