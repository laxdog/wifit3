"""Pure-protocol tests for the wildcard DNS encode/parse (no real socket)."""
import struct

from wifit3.net.dns import build_reply

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
