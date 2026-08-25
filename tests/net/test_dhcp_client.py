"""Pure-protocol tests for the DHCP client encode/parse (no real socket), plus the queue-based
request_lease loop that replaced the (kernel-broken, on an addressless interface) socket recv."""
import asyncio
import struct

from wifit3.net.dhcp_client import (
    ACK, DISCOVER, OFFER, REQUEST, build_discover, build_request, extract_bootp, parse_reply,
    request_lease, wrap_ethernet,
)

_MAC = bytes.fromhex("02aabbccddee")
_XID = bytes.fromhex("11223344")


def test_build_discover_layout():
    f = build_discover(_MAC, _XID)
    assert f[0] == 1                                       # BOOTREQUEST
    assert f[4:8] == _XID
    assert f[28:34] == _MAC
    assert f[236:240] == bytes.fromhex("63825363")
    assert _find_opt(f[240:], 53) == bytes([DISCOVER])
    assert _find_opt(f[240:], 50) is None                   # no requested-IP on a DISCOVER


def test_build_request_carries_requested_ip_and_server_id():
    f = build_request(_MAC, _XID, "10.13.37.100", "10.13.37.1")
    assert _find_opt(f[240:], 53) == bytes([REQUEST])
    assert _find_opt(f[240:], 50) == bytes([10, 13, 37, 100])
    assert _find_opt(f[240:], 54) == bytes([10, 13, 37, 1])


def _offer_packet(yiaddr="10.13.37.100", server_id="10.13.37.1", mask="255.255.255.0",
                  router="10.13.37.1", dns="10.13.37.1", msg_type=OFFER) -> bytes:
    header = (struct.pack("!BBBB", 2, 1, 6, 0) + _XID + b"\x00" * 4 + b"\x00" * 4
             + bytes(int(o) for o in yiaddr.split(".")) + b"\x00" * 8
             + _MAC + b"\x00" * 10 + b"\x00" * 64 + b"\x00" * 128
             + bytes.fromhex("63825363"))
    def opt(tag, ip):
        return bytes([tag, 4]) + bytes(int(o) for o in ip.split("."))
    opts = (bytes([53, 1, msg_type]) + opt(1, mask) + opt(3, router) + opt(6, dns)
           + opt(54, server_id) + bytes([255]))
    return header + opts


def test_parse_reply_extracts_yiaddr_and_options():
    reply = parse_reply(_offer_packet())
    assert reply is not None
    assert reply.msg_type == OFFER and reply.xid == _XID and reply.yiaddr == "10.13.37.100"
    assert reply.options[1] == bytes([255, 255, 255, 0])    # subnet mask
    assert reply.options[3] == bytes([10, 13, 37, 1])         # router
    assert reply.options[54] == bytes([10, 13, 37, 1])        # server id


def test_parse_reply_rejects_client_originated_packet():
    bad = bytearray(_offer_packet())
    bad[0] = 1                                               # BOOTREQUEST, not a reply
    assert parse_reply(bytes(bad)) is None


def test_parse_reply_rejects_bad_magic_cookie():
    bad = bytearray(_offer_packet())
    bad[236:240] = b"\x00\x00\x00\x00"
    assert parse_reply(bytes(bad)) is None


def test_parse_reply_rejects_short_packet():
    assert parse_reply(b"\x02\x01\x06\x00") is None


def test_ack_distinguishable_from_offer():
    ack = parse_reply(_offer_packet(msg_type=ACK))
    assert ack is not None and ack.msg_type == ACK


# ----- wrap_ethernet: the frame is hand-built with src IP 0.0.0.0, never the kernel's pick -----
# (confirmed live: with no address on the sending interface yet, a normal socket send picks the
# *default route's* source IP instead -- the host's real address, not 0.0.0.0 -- which no real
# DHCP server would offer a lease against; this is why sends bypass the socket API entirely).

def test_wrap_ethernet_broadcast_addressing():
    f = wrap_ethernet(build_discover(_MAC, _XID), _MAC)
    assert f[0:6] == b"\xff\xff\xff\xff\xff\xff"             # eth dst: broadcast
    assert f[6:12] == _MAC                                    # eth src: us
    assert f[12:14] == b"\x08\x00"                             # ethertype: IPv4


def test_wrap_ethernet_ip_header_uses_0_0_0_0_source():
    f = wrap_ethernet(build_discover(_MAC, _XID), _MAC)
    ip = f[14:34]                                              # 20-byte IPv4 header, no options
    assert ip[12:16] == bytes(4)                                # src = 0.0.0.0
    assert ip[16:20] == b"\xff\xff\xff\xff"                     # dst = 255.255.255.255
    assert ip[9] == 17                                          # protocol = UDP


def test_wrap_ethernet_ip_checksum_is_valid():
    f = wrap_ethernet(build_discover(_MAC, _XID), _MAC)
    ip = f[14:34]
    words = struct.unpack("!10H", ip)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    assert (~total) & 0xFFFF == 0                              # a valid header checksums to 0


def test_wrap_ethernet_udp_ports():
    f = wrap_ethernet(build_discover(_MAC, _XID), _MAC)
    udp = f[34:42]
    sport, dport, length = struct.unpack("!HHH", udp[0:6])
    assert sport == 68 and dport == 67
    assert length == 8 + len(build_discover(_MAC, _XID))


def test_wrap_ethernet_carries_the_bootp_payload_unmodified():
    bootp = build_request(_MAC, _XID, "10.13.37.100", "10.13.37.1")
    f = wrap_ethernet(bootp, _MAC)
    assert f[42:] == bootp


# ----- extract_bootp / request_lease: replies arrive as decoded Ethernet frames off a queue,
# not a bound socket (a broadcast reply isn't kernel-delivered to one on an addressless
# interface, confirmed live) -----

def _reply_ethernet(bootp: bytes, dst_mac: bytes = _MAC) -> bytes:
    """Server -> client: src 10.13.37.1:67, dst broadcast:68 (mirrors wrap_ethernet, reply side)."""
    udp = struct.pack("!HHHH", 67, 68, 8 + len(bootp), 0) + bootp
    ip = (struct.pack("!BBHHHBB", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17)
         + b"\x00\x00" + bytes([10, 13, 37, 1]) + b"\xff\xff\xff\xff")
    return b"\xff\xff\xff\xff\xff\xff" + dst_mac + b"\x08\x00" + ip + udp


def test_extract_bootp_pulls_payload_from_a_dhcp_shaped_frame():
    bootp = _offer_packet()
    assert extract_bootp(_reply_ethernet(bootp)) == bootp


def test_extract_bootp_rejects_non_ipv4():
    frame = b"\xff" * 6 + _MAC + b"\x08\x06" + b"\x00" * 20
    assert extract_bootp(frame) is None


def test_extract_bootp_rejects_non_udp():
    eth = bytearray(_reply_ethernet(_offer_packet()))
    eth[14 + 9] = 6                                          # protocol = TCP, not UDP
    assert extract_bootp(bytes(eth)) is None


def test_extract_bootp_rejects_wrong_dest_port():
    eth = bytearray(_reply_ethernet(_offer_packet()))
    struct.pack_into("!H", eth, 14 + 20 + 2, 12345)            # dport != 68
    assert extract_bootp(bytes(eth)) is None


async def test_request_lease_full_round_trip_over_the_queue():
    frames: "asyncio.Queue[bytes]" = asyncio.Queue()
    sent: list[bytes] = []
    xid_box: list[bytes] = []

    def send_frame(frame: bytes) -> None:
        sent.append(frame)
        bootp = frame[42:]
        xid = bootp[4:8]
        xid_box.append(xid)
        msg_type = _find_opt(bootp[240:], 53)[0]
        if msg_type == DISCOVER:
            frames.put_nowait(_reply_ethernet(_offer_with_xid(xid, OFFER)))
        elif msg_type == REQUEST:
            frames.put_nowait(_reply_ethernet(_offer_with_xid(xid, ACK)))

    lease = await request_lease(_MAC, send_frame, frames, timeout=2.0, retries=2)
    assert lease is not None
    assert lease.ip == "10.13.37.100" and lease.router == "10.13.37.1" and lease.prefix == 24
    assert len(sent) == 2                                     # DISCOVER then REQUEST, no retries


async def test_request_lease_times_out_with_no_replies():
    frames: "asyncio.Queue[bytes]" = asyncio.Queue()
    lease = await request_lease(_MAC, lambda f: None, frames, timeout=0.2, retries=2)
    assert lease is None


async def test_request_lease_ignores_replies_for_a_different_xid():
    frames: "asyncio.Queue[bytes]" = asyncio.Queue()

    def send_frame(frame: bytes) -> None:
        frames.put_nowait(_reply_ethernet(_offer_with_xid(b"\x99\x99\x99\x99", OFFER)))

    lease = await request_lease(_MAC, send_frame, frames, timeout=0.3, retries=2)
    assert lease is None


def _offer_with_xid(xid: bytes, msg_type: int) -> bytes:
    p = bytearray(_offer_packet(msg_type=msg_type))
    p[4:8] = xid
    return bytes(p)


def _find_opt(opts: bytes, tag: int):
    i = 0
    while i < len(opts) and opts[i] != 255:
        t, length = opts[i], opts[i + 1]
        if t == tag:
            return opts[i + 2:i + 2 + length]
        i += 2 + length
    return None
