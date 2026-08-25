"""Pure-protocol tests for the wildcard DNS encode/parse (no real socket), plus DnsServer's
authorized-client forwarding path (sockets mocked out)."""
import struct
from unittest.mock import MagicMock, mock_open, patch

from wifit3.net.dns import DnsServer, build_reply, system_resolver

_ID = b"\x12\x34"


def _query(name: str, qtype: int) -> bytes:
    header = _ID + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)   # RD=1, one question
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", qtype, 1)
    return header + question


def test_a_query_answers_with_our_ip():
    reply = build_reply(_query("captive.apple.com", 1), "10.13.37.1")
    assert reply[0:2] == _ID
    flags = struct.unpack_from("!H", reply, 2)[0]
    assert flags & 0x8000                                # QR: response
    ancount = struct.unpack_from("!H", reply, 6)[0]
    assert ancount == 1
    assert reply[-4:] == bytes([10, 13, 37, 1])


def test_aaaa_query_gets_no_answer():
    reply = build_reply(_query("connectivitycheck.gstatic.com", 28), "10.13.37.1")
    ancount = struct.unpack_from("!H", reply, 6)[0]
    assert ancount == 0
    # RCODE must still be NOERROR (not NXDOMAIN): a client shouldn't give up on the name outright.
    flags = struct.unpack_from("!H", reply, 2)[0]
    assert (flags & 0x000F) == 0


def test_malformed_query_returns_none():
    assert build_reply(b"\x00\x01", "10.13.37.1") is None


def test_reply_preserves_transaction_id_and_question():
    q = _query("www.msftconnecttest.com", 1)
    reply = build_reply(q, "10.13.37.1")
    assert reply[0:2] == q[0:2]
    # Question section (after the 12-byte header) must be echoed back unmodified.
    assert reply[12:12 + len(q) - 12] == q[12:]


# ----- system_resolver: piggyback on the host's own configured DNS server, not a hardcoded
# public one -- that can be slow or firewalled on networks that only allow the DHCP-assigned
# resolver out, while the host's own resolver is guaranteed reachable -----------------------

def test_system_resolver_reads_first_nameserver():
    conf = "# generated\nnameserver 192.168.1.1\nnameserver 8.8.8.8\n"
    with patch("builtins.open", mock_open(read_data=conf)):
        assert system_resolver() == "192.168.1.1"


def test_system_resolver_falls_back_when_resolv_conf_missing():
    with patch("builtins.open", side_effect=OSError):
        assert system_resolver() == "1.1.1.1"


def test_system_resolver_falls_back_when_no_nameserver_line():
    with patch("builtins.open", mock_open(read_data="# empty\nsearch example.com\n")):
        assert system_resolver() == "1.1.1.1"


def test_dns_server_defaults_upstream_to_system_resolver():
    with patch("wifit3.net.dns.system_resolver", return_value="192.168.1.1"):
        srv = DnsServer("wifit3tap0", answer_ip="10.13.37.1")
    assert srv.upstream == "192.168.1.1"


def test_dns_server_explicit_upstream_overrides_system_resolver():
    srv = DnsServer("wifit3tap0", answer_ip="10.13.37.1", upstream="9.9.9.9")
    assert srv.upstream == "9.9.9.9"


# ----- DnsServer: authorized clients get forwarded to a real resolver instead of wildcarded,
# or NAT's internet sharing would be pointless -- every hostname would still resolve to us -----

def _server(authorized=None) -> DnsServer:
    srv = DnsServer("wifit3tap0", answer_ip="10.13.37.1", authorized=authorized)
    srv._sock = MagicMock()
    srv._upstream_sock = MagicMock()
    return srv


def test_unauthorized_client_gets_the_wildcard_answer():
    srv = _server()
    q = _query("example.com", 1)
    srv._sock.recvfrom.return_value = (q, ("10.13.37.100", 5353))
    srv._on_readable()
    srv._sock.sendto.assert_called_once()
    sent, addr = srv._sock.sendto.call_args.args
    assert addr == ("10.13.37.100", 5353)
    assert sent[-4:] == bytes([10, 13, 37, 1])
    srv._upstream_sock.sendto.assert_not_called()


def test_authorized_client_query_is_forwarded_upstream_not_wildcarded():
    srv = _server(authorized={"10.13.37.100"})
    q = _query("example.com", 1)
    srv._sock.recvfrom.return_value = (q, ("10.13.37.100", 5353))
    srv._on_readable()
    srv._sock.sendto.assert_not_called()               # no wildcard lie to an authorized client
    srv._upstream_sock.sendto.assert_called_once_with(q, (srv.upstream, 53))
    assert srv._pending[q[0:2]] == ("10.13.37.100", 5353)


def test_upstream_reply_relayed_back_to_the_original_client():
    srv = _server(authorized={"10.13.37.100"})
    q = _query("example.com", 1)
    srv._pending[q[0:2]] = ("10.13.37.100", 5353)
    real_reply = q[0:2] + b"\x81\x80" + q[4:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" \
                + bytes([93, 184, 216, 34])
    srv._upstream_sock.recvfrom.return_value = (real_reply, ("1.1.1.1", 53))
    srv._on_upstream_readable()
    srv._sock.sendto.assert_called_once_with(real_reply, ("10.13.37.100", 5353))
    assert q[0:2] not in srv._pending                    # consumed, not leaked


def test_upstream_reply_with_unknown_transaction_id_is_dropped():
    srv = _server(authorized={"10.13.37.100"})
    srv._upstream_sock.recvfrom.return_value = (b"\x99\x99\x81\x80", ("1.1.1.1", 53))
    srv._on_upstream_readable()
    srv._sock.sendto.assert_not_called()


def test_pending_map_is_bounded():
    srv = _server(authorized={"10.13.37.100"})
    for i in range(300):
        srv._forward(struct.pack("!H", i) + b"rest", ("10.13.37.100", 5353))
    assert len(srv._pending) <= 256
