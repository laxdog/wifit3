"""dns_client: pure wire-format encode/parse (build_query/parse_a_answer), plus resolve() with
the real socket mocked out -- matches dhcp_client.py's test split for the same reasons."""
import asyncio
import struct

from wifit3.net.dns_client import build_query, parse_a_answer, resolve

_QID = bytes.fromhex("1234")


def _a_reply(qid: bytes, name: str, ip: str) -> bytes:
    header = qid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
             + bytes(int(o) for o in ip.split(".")))
    return header + question + answer


def test_build_query_layout():
    q = build_query("captive.apple.com", _QID)
    assert q[0:2] == _QID
    assert q[4:6] == struct.pack("!H", 1)               # QDCOUNT=1
    assert b"\x07captive\x05apple\x03com\x00" in q
    assert q[-4:] == struct.pack("!HH", 1, 1)            # QTYPE=A, QCLASS=IN


def test_parse_a_answer_extracts_the_ip():
    reply = _a_reply(_QID, "captive.apple.com", "17.253.0.1")
    assert parse_a_answer(reply, _QID) == "17.253.0.1"


def test_parse_a_answer_rejects_mismatched_qid():
    reply = _a_reply(_QID, "captive.apple.com", "17.253.0.1")
    assert parse_a_answer(reply, bytes.fromhex("9999")) is None


def test_parse_a_answer_none_when_no_answers():
    header = _QID + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0)   # NXDOMAIN, no answer
    qname = b"\x07captive\x05apple\x03com\x00"
    packet = header + qname + struct.pack("!HH", 1, 1)
    assert parse_a_answer(packet, _QID) is None


def test_parse_a_answer_rejects_short_packet():
    assert parse_a_answer(b"\x12\x34", _QID) is None


async def test_resolve_sends_query_and_parses_the_reply(mocker):
    reply = _a_reply(_QID, "captive.apple.com", "17.253.0.1")
    mocker.patch("os.urandom", return_value=_QID)
    fake_sock = mocker.MagicMock()
    mocker.patch("socket.socket", return_value=fake_sock)

    class _FakeLoop:
        async def sock_sendto(self, sock, data, addr):
            self.sent = (data, addr)

        async def sock_recv(self, sock, size):
            return reply

    mocker.patch("asyncio.get_running_loop", return_value=_FakeLoop())
    result = await resolve("wifit3fetch0", "10.0.0.1", "captive.apple.com")
    assert result == "17.253.0.1"
    fake_sock.close.assert_called_once()


async def test_resolve_returns_none_on_timeout(mocker):
    mocker.patch("socket.socket")

    class _FakeLoop:
        async def sock_sendto(self, sock, data, addr):
            pass

        def sock_recv(self, sock, size):
            return None                     # never reached: the mocked wait_for times out first

    mocker.patch("asyncio.get_running_loop", return_value=_FakeLoop())
    mocker.patch("asyncio.wait_for", side_effect=asyncio.TimeoutError)
    assert await resolve("wifit3fetch0", "10.0.0.1", "captive.apple.com") is None


async def test_resolve_returns_none_on_socket_error(mocker):
    fake_sock = mocker.MagicMock()
    fake_sock.setsockopt.side_effect = OSError("no such device")
    mocker.patch("socket.socket", return_value=fake_sock)
    assert await resolve("wifit3fetch0", "10.0.0.1", "captive.apple.com") is None
