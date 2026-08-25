"""HttpPortalServer request handling, over a loopback socket (bypasses TAP/SO_BINDTODEVICE/
privileged-port setup entirely: only ``_handle`` is under test, not ``start()``)."""
import asyncio

import pytest

from wifit3.net.http_portal import HttpPortalServer

_PAGE = "<html>portal</html>"


@pytest.fixture
async def server():
    srv = HttpPortalServer("wifit3tap0", page=_PAGE)
    asyncio_server = await asyncio.start_server(srv._handle, host="127.0.0.1", port=0)
    port = asyncio_server.sockets[0].getsockname()[1]
    yield srv, port
    asyncio_server.close()
    await asyncio_server.wait_closed()


async def _request(port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    data = await reader.read(65536)
    writer.close()
    return data


async def test_get_root_serves_the_page(server):
    srv, port = server
    resp = await _request(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 200")
    assert _PAGE.encode() in resp


async def test_get_other_path_redirects_to_root(server):
    srv, port = server
    resp = await _request(port, b"GET /hotspot-detect.html HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 302")
    assert b"Location: /" in resp


async def test_post_captures_submitted_fields(server):
    srv, port = server
    body = b"password=hunter2"
    req = (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
          b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    resp = await _request(port, req)
    assert resp.startswith(b"HTTP/1.1 200")
    assert b"connected" in resp.lower()
    assert srv.submissions == [{"password": "hunter2"}]


async def test_on_submit_callback_fires():
    seen = []
    srv = HttpPortalServer("wifit3tap0", page=_PAGE, on_submit=seen.append)
    asyncio_server = await asyncio.start_server(srv._handle, host="127.0.0.1", port=0)
    port = asyncio_server.sockets[0].getsockname()[1]
    try:
        body = b"email=a%40b.com&password=x"
        req = (b"POST / HTTP/1.1\r\nHost: x\r\n"
              b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await _request(port, req)
    finally:
        asyncio_server.close()
        await asyncio_server.wait_closed()
    assert seen == [{"email": "a@b.com", "password": "x"}]


async def test_malformed_request_line_closes_without_crashing(server):
    srv, port = server
    resp = await _request(port, b"garbage\r\n\r\n")     # not "METHOD path ..." shaped
    assert resp == b""                                 # connection just closes, server stays up
    # the server is still serving afterward
    resp2 = await _request(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp2.startswith(b"HTTP/1.1 200")
