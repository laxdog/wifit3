"""Pure-protocol tests for the minimal DHCP encode/parse (no real socket), plus DhcpServer's
socket-teardown-on-failure path."""
import struct
from unittest.mock import MagicMock, patch

import pytest

from wifit3.net.dhcp import ACK, DISCOVER, DhcpServer, OFFER, build_reply, parse

_MAC = bytes.fromhex("02aabbccddee")
_XID = bytes.fromhex("11223344")


def _discover(requested_ip=None) -> bytes:
    header = (struct.pack("!BBBB", 1, 1, 6, 0) + _XID + b"\x00" * 4 + b"\x00" * 16
             + _MAC + b"\x00" * 10 + b"\x00" * 64 + b"\x00" * 128
             + bytes.fromhex("63825363"))
    opts = bytes([53, 1, DISCOVER])
    if requested_ip:
        opts += bytes([50, 4]) + bytes(int(p) for p in requested_ip.split("."))
    opts += bytes([255])
    return header + opts


def test_parse_discover_extracts_msg_type_xid_chaddr():
    req = parse(_discover())
    assert req is not None
    assert req.msg_type == DISCOVER and req.xid == _XID and req.chaddr == _MAC
    assert req.requested_ip is None


def test_parse_extracts_requested_ip_option():
    req = parse(_discover(requested_ip="10.13.37.5"))
    assert req.requested_ip == "10.13.37.5"


def test_parse_rejects_short_packet():
    assert parse(b"\x01\x01\x06\x00") is None


def test_parse_rejects_bad_magic_cookie():
    bad = bytearray(_discover())
    bad[236:240] = b"\x00\x00\x00\x00"
    assert parse(bytes(bad)) is None


def test_parse_rejects_server_originated_packet():
    # op=2 (BOOTREPLY) is a server->client packet; parse() only understands client requests.
    bad = bytearray(_discover())
    bad[0] = 2
    assert parse(bytes(bad)) is None


def test_build_reply_offer_layout():
    f = build_reply(msg_type=OFFER, xid=_XID, chaddr=_MAC, your_ip="10.13.37.100",
                    server_ip="10.13.37.1", router_ip="10.13.37.1", dns_ip="10.13.37.1")
    assert f[0] == 2                                       # BOOTREPLY
    assert f[4:8] == _XID
    assert f[16:20] == bytes([10, 13, 37, 100])             # yiaddr
    assert f[28:34] == _MAC
    assert f[236:240] == bytes.fromhex("63825363")
    reparsed_type = _find_opt(f[240:], 53)
    assert reparsed_type == bytes([OFFER])
    assert _find_opt(f[240:], 1) == bytes([255, 255, 255, 0])   # /24 mask
    assert _find_opt(f[240:], 3) == bytes([10, 13, 37, 1])       # router


def test_build_reply_ack_carries_offer_type_distinctly():
    offer = build_reply(msg_type=OFFER, xid=_XID, chaddr=_MAC, your_ip="10.13.37.100",
                        server_ip="10.13.37.1", router_ip="10.13.37.1", dns_ip="10.13.37.1")
    ack = build_reply(msg_type=ACK, xid=_XID, chaddr=_MAC, your_ip="10.13.37.100",
                      server_ip="10.13.37.1", router_ip="10.13.37.1", dns_ip="10.13.37.1")
    assert _find_opt(offer[240:], 53) == bytes([OFFER])
    assert _find_opt(ack[240:], 53) == bytes([ACK])


def test_start_closes_the_socket_on_a_non_permission_bind_failure():
    """Only PermissionError used to close the socket before re-raising; any other bind failure
    (e.g. EADDRINUSE from a leftover run) leaked the fd instead."""
    srv = DhcpServer("wifit3tap0", server_ip="10.13.37.1", pool_start="10.13.37.100")
    sock = MagicMock()
    sock.bind.side_effect = OSError("Address already in use")
    with patch("wifit3.net.dhcp.socket.socket", return_value=sock):
        with pytest.raises(OSError):
            srv.start()
    sock.close.assert_called_once()


def _find_opt(opts: bytes, tag: int):
    i = 0
    while i < len(opts) and opts[i] != 255:
        t, length = opts[i], opts[i + 1]
        if t == tag:
            return opts[i + 2:i + 2 + length]
        i += 2 + length
    return None
