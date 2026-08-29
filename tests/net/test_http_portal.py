"""HttpPortalServer request handling, over a loopback socket (bypasses TAP/SO_BINDTODEVICE/
privileged-port setup entirely: only ``_handle`` is under test, not ``start()``), plus a
dedicated ``start()`` socket-teardown-on-failure test below."""
import asyncio
from unittest.mock import MagicMock, patch

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


async def test_get_check_path_redirects_to_root_when_unauthorized(server):
    """An OS's own background connectivity-check GET must NOT count as a submission -- it fires
    on its own, with no user interaction, so treating it as one would auto-dismiss the portal
    before anyone ever saw or clicked anything."""
    srv, port = server
    resp = await _request(port, b"GET /hotspot-detect.html HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 302")
    assert b"Location: /" in resp
    assert srv.submissions == []


async def test_favicon_request_404s_without_authorizing(server):
    """A real browser requests /favicon.ico on every navigation whether or not the page declares
    one -- if that fell to the "real portal's own submit link" branch, it would silently
    pre-authorize the client before they ever saw the form."""
    srv, port = server
    resp = await _request(port, b"GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 404")
    assert srv.submissions == []


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


# ----- authorized clients: once a client has POSTed the form, its OS's own connectivity-check
# requests get the real "you have internet" response so the sign-in sheet auto-dismisses -----

async def test_authorized_client_gets_real_success_on_apple_check_path(server):
    srv, port = server
    body = b"password=hunter2"
    post = (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: " + str(len(body)).encode()
           + b"\r\n\r\n" + body)
    await _request(port, post)
    resp = await _request(port, b"GET /hotspot-detect.html HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 200")
    assert b"Success" in resp


async def test_authorized_client_gets_204_on_android_generate_204():
    srv = HttpPortalServer("wifit3tap0", page=_PAGE)
    asyncio_server = await asyncio.start_server(srv._handle, host="127.0.0.1", port=0)
    port = asyncio_server.sockets[0].getsockname()[1]
    try:
        await _request(port, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        resp = await _request(port, b"GET /generate_204 HTTP/1.1\r\nHost: x\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 204")
        assert resp.endswith(b"\r\n\r\n")               # no body
    finally:
        asyncio_server.close()
        await asyncio_server.wait_closed()


async def test_authorized_client_gets_windows_and_firefox_check_text():
    srv = HttpPortalServer("wifit3tap0", page=_PAGE)
    asyncio_server = await asyncio.start_server(srv._handle, host="127.0.0.1", port=0)
    port = asyncio_server.sockets[0].getsockname()[1]
    try:
        await _request(port, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        resp = await _request(port, b"GET /connecttest.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b"Microsoft Connect Test" in resp
        resp = await _request(port, b"GET /ncsi.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b"Microsoft NCSI" in resp
        resp = await _request(port, b"GET /success.txt HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b"success" in resp
    finally:
        asyncio_server.close()
        await asyncio_server.wait_closed()


async def test_unauthorized_client_still_redirected_from_check_paths(server):
    """Not yet signed in: the check paths must keep redirecting, or the sign-in sheet never
    shows up in the first place."""
    srv, port = server
    resp = await _request(port, b"GET /generate_204 HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 302")


async def test_authorized_client_gets_success_page_on_other_paths(server):
    """A signed-in client reloading some other page shouldn't loop back into the portal."""
    srv, port = server
    await _request(port, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    resp = await _request(port, b"GET /whatever HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 200")
    assert b"connected" in resp.lower()


async def test_apple_cna_post_gets_redirected_to_hotspot_detect(server):
    """CNA's own webview navigating to its check URL and seeing "Success" is what makes the
    sign-in sheet close itself immediately, instead of waiting on CNA's own background timer."""
    srv, port = server
    body = b"password=hunter2"
    req = (b"POST / HTTP/1.1\r\nHost: x\r\n"
          b"User-Agent: CaptiveNetworkSupport-359.60.4 wispr\r\n"
          b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    resp = await _request(port, req)
    assert resp.startswith(b"HTTP/1.1 302")
    assert b"Location: /hotspot-detect.html" in resp


async def test_non_apple_post_gets_the_normal_success_page(server):
    srv, port = server
    body = b"password=hunter2"
    req = (b"POST / HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\n"
          b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    resp = await _request(port, req)
    assert resp.startswith(b"HTTP/1.1 200")
    assert b"connected" in resp.lower()


# ----- GET-based real portals: nodogsplash and openNDS both submit their login/continue form
# via method="get", not POST -- an unrecognized GET must authorize just like a POST would ---------

async def test_unrecognized_get_path_authorizes_like_a_post_would(server):
    """The real portal's own submit/continue link (nodogsplash's $authaction, openNDS's
    /opennds_preauth/) is a plain GET with fields in the query string, not a POST body."""
    srv, port = server
    resp = await _request(port, b"GET /opennds_preauth/?fas=abc&continue=clicked HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 200")
    assert b"connected" in resp.lower()
    assert srv.submissions == [{"fas": "abc", "continue": "clicked"}]


async def test_get_submission_on_submit_callback_fires():
    seen = []
    srv = HttpPortalServer("wifit3tap0", page=_PAGE, on_submit=seen.append)
    asyncio_server = await asyncio.start_server(srv._handle, host="127.0.0.1", port=0)
    port = asyncio_server.sockets[0].getsockname()[1]
    try:
        await _request(port, b"GET /login?username=bob HTTP/1.1\r\nHost: x\r\n\r\n")
    finally:
        asyncio_server.close()
        await asyncio_server.wait_closed()
    assert seen == [{"username": "bob"}]


async def test_get_submission_authorizes_so_later_requests_get_success_page(server):
    srv, port = server
    await _request(port, b"GET /opennds_preauth/?continue=clicked HTTP/1.1\r\nHost: x\r\n\r\n")
    resp = await _request(port, b"GET /whatever HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 200")
    assert b"connected" in resp.lower()


# ----- page assets (icons/css/images referenced by the cloned page): must be served, and must
# NOT count as a submission -- otherwise the page's own incidental resource loads (which happen
# the instant the browser renders it, before any user interaction) would auto-authorize -----------

async def test_known_asset_is_served_without_authorizing():
    page = '<html><link rel="stylesheet" href="/splash.css"></html>'
    srv = HttpPortalServer("wifit3tap0", page=page,
                           assets={"/splash.css": ("text/css", b".x{color:red}")})
    asyncio_server = await asyncio.start_server(srv._handle, host="127.0.0.1", port=0)
    port = asyncio_server.sockets[0].getsockname()[1]
    try:
        resp = await _request(port, b"GET /splash.css HTTP/1.1\r\nHost: x\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 200")
        assert b"Content-Type: text/css" in resp
        assert b".x{color:red}" in resp
        assert srv.submissions == []
    finally:
        asyncio_server.close()
        await asyncio_server.wait_closed()


async def test_referenced_but_unfetched_asset_404s_without_authorizing():
    """The asset was referenced in the page but fetching it failed (real target down/blocked):
    404, not a redirect-loop back to "/" and not treated as a form submission either."""
    page = '<html><img src="/missing.jpg"></html>'
    srv = HttpPortalServer("wifit3tap0", page=page)   # no assets provided
    asyncio_server = await asyncio.start_server(srv._handle, host="127.0.0.1", port=0)
    port = asyncio_server.sockets[0].getsockname()[1]
    try:
        resp = await _request(port, b"GET /missing.jpg HTTP/1.1\r\nHost: x\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 404")
        assert srv.submissions == []
    finally:
        asyncio_server.close()
        await asyncio_server.wait_closed()


async def test_start_closes_the_socket_on_a_non_permission_bind_failure():
    """Only PermissionError used to close the socket before re-raising; any other bind failure
    (e.g. EADDRINUSE from a leftover run) leaked the fd instead."""
    srv = HttpPortalServer("wifit3tap0", page=_PAGE)
    sock = MagicMock()
    sock.bind.side_effect = OSError("Address already in use")
    with patch("wifit3.net.http_portal.socket.socket", return_value=sock):
        with pytest.raises(OSError):
            await srv.start()
    sock.close.assert_called_once()


async def test_malformed_request_line_closes_without_crashing(server):
    srv, port = server
    resp = await _request(port, b"garbage\r\n\r\n")     # not "METHOD path ..." shaped
    assert resp == b""                                 # connection just closes, server stays up
    # the server is still serving afterward
    resp2 = await _request(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert resp2.startswith(b"HTTP/1.1 200")
