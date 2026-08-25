"""portal_http_client: the HTTP GET/redirect logic, tested over a loopback socket (``_request``)
and with the scoped-socket connect mocked out entirely (``fetch_portal_page``, via ``_get``) --
neither touches a real TAP or needs CAP_NET_RAW, matching net/http_portal.py's test split."""
import asyncio

import pytest

from wifit3.net import portal_http_client as phc
from wifit3.net.http_portal import HttpPortalServer
from wifit3.net.portal_templates import PortalTemplate, render

_PORTAL_HTML = "<html>login please</html>"


@pytest.fixture
async def loopback_server():
    async def handler(reader, writer):
        request = await reader.readline()
        path = request.decode().split()[1] if request else "/"
        if path == "/redirect-me":
            writer.write(b"HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n")
        elif path == "/no-content-length":
            writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + _PORTAL_HTML.encode())
        else:
            body = _PORTAL_HTML.encode()
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handler, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


async def _connect(port):
    return await asyncio.open_connection("127.0.0.1", port)


async def test_request_parses_200_with_content_length(loopback_server):
    reader, writer = await _connect(loopback_server)
    status, headers, body = await phc._request(reader, writer, "x", 80, "/", 3)
    assert status == 200 and body == _PORTAL_HTML.encode()


async def test_request_parses_redirect_with_location(loopback_server):
    reader, writer = await _connect(loopback_server)
    status, headers, body = await phc._request(reader, writer, "x", 80, "/redirect-me", 3)
    assert status == 302 and headers["location"] == "/"


async def test_request_falls_back_to_read_until_close_with_no_content_length(loopback_server):
    reader, writer = await _connect(loopback_server)
    status, headers, body = await phc._request(reader, writer, "x", 80, "/no-content-length", 3)
    assert status == 200 and body == _PORTAL_HTML.encode()


async def test_request_sends_the_port_in_the_host_header_when_non_80(loopback_server):
    """HTTP/1.1 requires Host: to carry the port when it's not the default -- nodogsplash's own
    redirect-vs-serve routing (GatewayPort 2050) depends on seeing it."""
    reader, writer = await _connect(loopback_server)
    sent = []
    real_write = writer.write
    writer.write = lambda data: (sent.append(data), real_write(data))[1]
    await phc._request(reader, writer, "192.168.9.1", 2050, "/splash.html", 3)
    assert b"Host: 192.168.9.1:2050\r\n" in sent[0]


async def test_request_returns_none_status_on_garbage_response():
    class _Reader:
        async def readline(self):
            return b"not an http response\r\n"

    class _Writer:
        def write(self, data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

    status, headers, body = await phc._request(_Reader(), _Writer(), "x", 80, "/", 3)
    assert status is None and body is None


# ----- fetch_portal_page: redirect-following orchestration (``_get`` mocked) -----------------

async def test_fetch_returns_body_on_direct_200(mocker):
    mocker.patch.object(phc, "_get", mocker.AsyncMock(return_value=(200, {}, _PORTAL_HTML.encode())))
    result = await phc.fetch_portal_page("wifit3fetch0", "10.0.0.1")
    assert result == _PORTAL_HTML


async def test_fetch_follows_one_redirect_then_returns_body(mocker):
    calls = []

    async def fake_get(tap_name, host, port, path, timeout, *, dns_ip=None):
        calls.append((host, port, path))
        if len(calls) == 1:
            return 302, {"location": "/login.html"}, None
        return 200, {}, _PORTAL_HTML.encode()

    mocker.patch.object(phc, "_get", fake_get)
    result = await phc.fetch_portal_page("wifit3fetch0", "10.0.0.1")
    assert result == _PORTAL_HTML
    assert calls[0][2] == "/" and calls[1][2] == "/login.html"


async def test_fetch_gives_up_after_too_many_redirects(mocker):
    mocker.patch.object(phc, "_get", mocker.AsyncMock(
        return_value=(302, {"location": "/"}, None)))
    result = await phc.fetch_portal_page("wifit3fetch0", "10.0.0.1")
    assert result is None


async def test_fetch_does_not_chase_an_https_redirect(mocker):
    mocker.patch.object(phc, "_get", mocker.AsyncMock(
        return_value=(302, {"location": "https://example.com/login"}, None)))
    result = await phc.fetch_portal_page("wifit3fetch0", "10.0.0.1")
    assert result is None


async def test_fetch_chases_a_same_scheme_redirect_to_a_non_80_port(mocker):
    """nodogsplash's default GatewayPort is 2050: a plain-HTTP redirect to a non-80 port must
    still be followed, connecting to THAT port -- rejecting any non-80 port here (mistaking it
    for HTTPS) was a real bug that broke real nodogsplash portals."""
    calls = []

    async def fake_get(tap_name, host, port, path, timeout, *, dns_ip=None):
        calls.append((host, port, path))
        if len(calls) == 1:
            return 302, {"location": "http://10.0.0.1:2050/splash"}, None
        return 200, {}, _PORTAL_HTML.encode()

    mocker.patch.object(phc, "_get", fake_get)
    result = await phc.fetch_portal_page("wifit3fetch0", "10.0.0.1")
    assert result == _PORTAL_HTML
    assert calls[1] == ("10.0.0.1", 2050, "/splash")


async def test_fetch_chases_a_schemeless_redirect_to_a_non_80_port(mocker):
    """A protocol-relative Location (e.g. "//10.0.0.1:2050/splash", no scheme) is still HTTP."""
    calls = []

    async def fake_get(tap_name, host, port, path, timeout, *, dns_ip=None):
        calls.append((host, port, path))
        if len(calls) == 1:
            return 302, {"location": "//10.0.0.1:2050/splash"}, None
        return 200, {}, _PORTAL_HTML.encode()

    mocker.patch.object(phc, "_get", fake_get)
    result = await phc.fetch_portal_page("wifit3fetch0", "10.0.0.1")
    assert result == _PORTAL_HTML
    assert calls[1] == ("10.0.0.1", 2050, "/splash")


async def test_fetch_returns_none_when_connection_fails(mocker):
    mocker.patch.object(phc, "_get", mocker.AsyncMock(return_value=(None, {}, None)))
    assert await phc.fetch_portal_page("wifit3fetch0", "10.0.0.1") is None


async def test_fetch_returns_none_for_a_non_200_non_redirect_status(mocker):
    mocker.patch.object(phc, "_get", mocker.AsyncMock(return_value=(404, {}, "nope")))
    assert await phc.fetch_portal_page("wifit3fetch0", "10.0.0.1") is None


async def test_fetch_starts_from_a_custom_path(mocker):
    """The probe-host fallback needs a non-``/`` starting path (e.g. hotspot-detect.html)."""
    get = mocker.patch.object(phc, "_get", mocker.AsyncMock(return_value=(200, {}, _PORTAL_HTML.encode())))
    await phc.fetch_portal_page("wifit3fetch0", "10.0.0.1", path="/hotspot-detect.html")
    assert get.call_args.args[3] == "/hotspot-detect.html"


# ----- fetch_page_with_assets: same-page <img>/<link>/<script> refs fetched too, from wherever
# the page itself landed (not port 80, which just redirects any path back to the login page) -----

async def test_fetch_with_assets_fetches_referenced_css_from_the_pages_own_host_and_port(mocker):
    page_html = '<html><link rel="stylesheet" href="/splash.css"></html>'
    calls = []

    async def fake_get(tap_name, host, port, path, timeout, *, dns_ip=None):
        calls.append((host, port, path))
        if path == "/":
            # the login page itself redirects off to the real GatewayPort, same as nodogsplash/openNDS
            if len(calls) == 1:
                return 302, {"location": "http://10.0.0.1:2050/"}, None
            return 200, {}, page_html.encode()
        assert (host, port) == ("10.0.0.1", 2050)   # asset fetched from the landed host:port, not :80
        return 200, {}, b".offset{color:red}"

    mocker.patch.object(phc, "_get", fake_get)
    page, assets = await phc.fetch_page_with_assets("wifit3fetch0", "10.0.0.1")
    assert page == page_html
    assert assets == {"/splash.css": ("text/css", b".offset{color:red}")}


async def test_fetch_with_assets_skips_a_ref_that_fails_to_fetch(mocker):
    page_html = '<html><img src="/missing.jpg"></html>'
    mocker.patch.object(phc, "_get", mocker.AsyncMock(return_value=(200, {}, page_html.encode())))
    async_get = phc._get

    async def fake_get(tap_name, host, port, path, timeout, *, dns_ip=None):
        if path == "/missing.jpg":
            return 404, {}, b"nope"
        return await async_get(tap_name, host, port, path, timeout, dns_ip=dns_ip)

    mocker.patch.object(phc, "_get", fake_get)
    page, assets = await phc.fetch_page_with_assets("wifit3fetch0", "10.0.0.1")
    assert page == page_html
    assert assets == {}


async def test_fetch_with_assets_returns_empty_dict_when_page_fetch_fails(mocker):
    mocker.patch.object(phc, "_get", mocker.AsyncMock(return_value=(None, {}, None)))
    page, assets = await phc.fetch_page_with_assets("wifit3fetch0", "10.0.0.1")
    assert page is None and assets == {}


# ----- hostname redirects: a Location with a hostname (not a bare IP) needs DNS, since sock_connect
# can't resolve one itself and the OS resolver isn't scoped to this TAP -----------------------

async def test_get_resolves_a_hostname_target_via_the_supplied_dns_ip(mocker):
    resolve = mocker.patch.object(phc, "resolve_dns", mocker.AsyncMock(return_value="10.0.0.9"))
    mocker.patch.object(phc.socket, "socket", return_value=mocker.MagicMock())
    connect_calls = []

    class _FakeLoop:
        async def sock_connect(self, sock, addr):
            connect_calls.append(addr)
            raise OSError("stop here: connect behavior isn't under test")

    mocker.patch("asyncio.get_running_loop", return_value=_FakeLoop())
    status, headers, body = await phc._get("wifit3fetch0", "guest.example.com", 80, "/", 3,
                                           dns_ip="10.0.0.1")
    assert status is None
    resolve.assert_awaited_once_with("wifit3fetch0", "10.0.0.1", "guest.example.com", timeout=3)
    assert connect_calls == [("10.0.0.9", 80)]


async def test_get_gives_up_immediately_when_hostname_and_no_dns_ip():
    status, headers, body = await phc._get("wifit3fetch0", "guest.example.com", 80, "/", 3)
    assert status is None and headers == {} and body is None


async def test_get_skips_resolution_for_a_bare_ip(mocker):
    resolve = mocker.patch.object(phc, "resolve_dns")
    mocker.patch.object(phc.socket, "socket", return_value=mocker.MagicMock())

    class _FakeLoop:
        async def sock_connect(self, sock, addr):
            raise OSError("stop here: connect behavior isn't under test")

    mocker.patch("asyncio.get_running_loop", return_value=_FakeLoop())
    await phc._get("wifit3fetch0", "10.0.0.1", 80, "/", 3, dns_ip="10.0.0.1")
    resolve.assert_not_called()


# ----- end-to-end against the real HttpPortalServer, serving a real template -------------------
# (the same server class EvilTwin's own twin uses) -- this is the shape a real captive portal
# clone-fetch actually exercises: our client hitting our own server's exact byte output.

@pytest.mark.parametrize("template", list(PortalTemplate))
async def test_request_retrieves_a_real_template_byte_for_byte(template):
    page = render(template, "Airport Free WiFi")
    srv = HttpPortalServer("wifit3tap0", page=page)
    server = await asyncio.start_server(srv._handle, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        status, headers, body = await phc._request(reader, writer, "127.0.0.1", port, "/", 3)
        assert status == 200 and body == page.encode()
    finally:
        server.close()
        await server.wait_closed()
