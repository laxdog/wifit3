"""portal_fetch: orchestration of the real-portal client-role fetch (Association, ClientBridge,
DHCP, and HTTP are all mocked -- no real hardware, sockets, or TAP touched)."""
from wifit3.campaigns.eviltwin import portal_fetch as pf
from wifit3.dot11 import str_to_mac
from wifit3.net.dhcp_client import DhcpLease

_BSSID = "94:83:c4:8c:3f:78"


class _FakeLease:
    def __init__(self, iface, mac=None):
        self.iface = iface
        self.mac = mac

    async def __aenter__(self):
        return self.iface

    async def __aexit__(self, *exc):
        return False


class _FakeArray:
    def __init__(self, iface, mac=None):
        self.iface = iface
        self.mac = mac

    def lease(self, channel=None, fake_mac=None, bssid=None, iface=None, ack_tally=False):
        return _FakeLease(iface or self.iface, mac=self.mac)


class _FakeIface:
    def __init__(self):
        self.sent: list = []

    async def send_no_wait(self, frame) -> bool:
        self.sent.append(frame)
        return True


def _mock_association(mocker, ok: bool, fail_reason=None):
    return mocker.patch.object(pf, "Association", return_value=mocker.MagicMock(
        start=mocker.MagicMock(), stop=mocker.MagicMock(),
        associate=mocker.AsyncMock(return_value=ok), fail_reason=fail_reason))


async def test_fetch_returns_none_when_association_fails(mocker):
    iface = _FakeIface()
    _mock_association(mocker, ok=False, fail_reason="no Assoc resp")
    result = await pf.fetch_real_portal(_FakeArray(iface), iface, _BSSID, "TestNet", 6)
    assert result.page is None
    assert "no Assoc resp" in result.status


async def test_fetch_returns_none_when_dhcp_fails(mocker):
    iface = _FakeIface()
    _mock_association(mocker, ok=True)
    mocker.patch.object(pf, "ClientBridge", return_value=mocker.MagicMock(
        start=mocker.MagicMock(), stop=mocker.MagicMock(), tap=mocker.MagicMock()))
    mocker.patch.object(pf, "request_lease", mocker.AsyncMock(return_value=None))
    result = await pf.fetch_real_portal(_FakeArray(iface), iface, _BSSID, "TestNet", 6)
    assert result.page is None
    assert "no DHCP lease" in result.status


async def test_fetch_returns_page_on_full_success(mocker):
    iface = _FakeIface()
    _mock_association(mocker, ok=True)
    bridge = mocker.MagicMock(start=mocker.MagicMock(), stop=mocker.MagicMock(),
                              tap=mocker.MagicMock())
    mocker.patch.object(pf, "ClientBridge", return_value=bridge)
    lease = mocker.MagicMock(ip="10.0.0.5", prefix=24, router="10.0.0.1")
    mocker.patch.object(pf, "request_lease", mocker.AsyncMock(return_value=lease))
    mocker.patch.object(pf, "fetch_portal_page", mocker.AsyncMock(return_value="<html>portal</html>"))

    result = await pf.fetch_real_portal(_FakeArray(iface), iface, _BSSID, "TestNet", 6)

    assert result.page == "<html>portal</html>"
    assert "gateway" in result.status
    bridge.tap.add_address.assert_called_once_with("10.0.0.5", 24, gateway="10.0.0.1")
    bridge.start.assert_called_once()
    bridge.stop.assert_called_once()


async def test_fetch_sends_a_leaving_frame_even_on_failure(mocker):
    iface = _FakeIface()
    _mock_association(mocker, ok=False, fail_reason="timeout")
    await pf.fetch_real_portal(_FakeArray(iface), iface, _BSSID, "TestNet", 6)
    assert len(iface.sent) == 1                      # the client-leaving deauth


async def test_fetch_never_raises_on_unexpected_error(mocker):
    iface = _FakeIface()
    mocker.patch.object(pf, "Association", side_effect=RuntimeError("boom"))
    result = await pf.fetch_real_portal(_FakeArray(iface), iface, _BSSID, "TestNet", 6)
    assert result.page is None
    assert "boom" in result.status


async def test_fetch_reports_timeout_specifically(mocker):
    iface = _FakeIface()
    mocker.patch.object(pf, "_fetch", mocker.AsyncMock(side_effect=pf.asyncio.TimeoutError))
    result = await pf.fetch_real_portal(_FakeArray(iface), iface, _BSSID, "TestNet", 6)
    assert result.page is None
    assert "timed out" in result.status


# ----- _fetch_page: gateway-first, probe-host fallback when that comes back empty --------------

_LEASE = DhcpLease(ip="10.0.0.5", prefix=24, router="10.0.0.1", dns="10.0.0.1", server_id="10.0.0.1")
_LEASE_NO_DNS = DhcpLease(ip="10.0.0.5", prefix=24, router="10.0.0.1", dns=None, server_id="10.0.0.1")


async def test_fetch_page_returns_gateway_page_without_probing(mocker):
    get = mocker.patch.object(pf, "fetch_portal_page", mocker.AsyncMock(return_value="<html>x</html>"))
    resolve = mocker.patch.object(pf, "resolve_dns")
    result = await pf._fetch_page(_LEASE)
    assert result.page == "<html>x</html>"
    assert "gateway" in result.status
    get.assert_awaited_once_with(pf.TAP_NAME, "10.0.0.1", dns_ip="10.0.0.1", timeout=pf._HTTP_TIMEOUT)
    resolve.assert_not_called()


async def test_fetch_page_falls_back_to_probe_host_when_gateway_empty(mocker):
    mocker.patch.object(pf, "fetch_portal_page", mocker.AsyncMock(
        side_effect=[None, "<html>real portal</html>"]))
    resolve = mocker.patch.object(pf, "resolve_dns", mocker.AsyncMock(return_value="17.253.0.1"))
    result = await pf._fetch_page(_LEASE)
    assert result.page == "<html>real portal</html>"
    assert "probe-host" in result.status
    resolve.assert_awaited_once_with(pf.TAP_NAME, "10.0.0.1", pf._PROBE_HOST, timeout=pf._HTTP_TIMEOUT)


async def test_fetch_page_returns_none_when_probe_finds_real_internet(mocker):
    """The un-intercepted Apple response means there's no captive portal to clone."""
    mocker.patch.object(pf, "fetch_portal_page", mocker.AsyncMock(
        side_effect=[None, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"]))
    mocker.patch.object(pf, "resolve_dns", mocker.AsyncMock(return_value="17.253.0.1"))
    result = await pf._fetch_page(_LEASE)
    assert result.page is None
    assert "real internet" in result.status


async def test_fetch_page_skips_probe_without_dns(mocker):
    mocker.patch.object(pf, "fetch_portal_page", mocker.AsyncMock(return_value=None))
    resolve = mocker.patch.object(pf, "resolve_dns")
    result = await pf._fetch_page(_LEASE_NO_DNS)
    assert result.page is None
    assert "no DNS server" in result.status
    resolve.assert_not_called()


async def test_fetch_page_returns_none_when_probe_host_does_not_resolve(mocker):
    mocker.patch.object(pf, "fetch_portal_page", mocker.AsyncMock(return_value=None))
    mocker.patch.object(pf, "resolve_dns", mocker.AsyncMock(return_value=None))
    result = await pf._fetch_page(_LEASE)
    assert result.page is None
    assert "couldn't resolve" in result.status


async def test_fetch_page_returns_none_when_both_gateway_and_probe_fail(mocker):
    mocker.patch.object(pf, "fetch_portal_page", mocker.AsyncMock(return_value=None))
    mocker.patch.object(pf, "resolve_dns", mocker.AsyncMock(return_value="17.253.0.1"))
    result = await pf._fetch_page(_LEASE)
    assert result.page is None
    assert "HTTPS" in result.status


async def test_fetch_uses_the_armed_mac_from_the_lease(mocker):
    iface = _FakeIface()
    armed_mac = "02:11:22:33:44:55"
    captured = {}

    def fake_association(iface_, bssid, ssid, channel, our_mac=None, **kw):
        captured["our_mac"] = our_mac
        return mocker.MagicMock(start=mocker.MagicMock(), stop=mocker.MagicMock(),
                                associate=mocker.AsyncMock(return_value=False), fail_reason="x")

    mocker.patch.object(pf, "Association", side_effect=fake_association)
    await pf.fetch_real_portal(_FakeArray(iface, mac=armed_mac), iface, _BSSID, "TestNet", 6)
    assert captured["our_mac"] == str_to_mac(armed_mac)
