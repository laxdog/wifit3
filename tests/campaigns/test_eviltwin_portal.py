"""PortalStack: start/stop orchestration and rollback (bridge/dns/http mocked; no real TAP or
sockets)."""
from wifit3.campaigns.eviltwin.portal import PortalStack

_BSSID = bytes.fromhex("9483c48c3f78")


def _stack(mocker) -> PortalStack:
    stack = PortalStack(twin_iface=mocker.MagicMock(), bssid=_BSSID, ssid="GL-Test")
    stack.bridge = mocker.MagicMock(start=mocker.MagicMock(), stop=mocker.MagicMock())
    stack.dns = mocker.MagicMock(start=mocker.MagicMock(), stop=mocker.MagicMock())
    stack.http = mocker.MagicMock(start=mocker.AsyncMock(), stop=mocker.AsyncMock())
    stack.nat = mocker.MagicMock(start=mocker.MagicMock(), stop=mocker.MagicMock(), uplink=None)
    return stack


async def test_start_brings_up_bridge_then_dns_then_http(mocker):
    stack = _stack(mocker)
    await stack.start()
    stack.bridge.start.assert_called_once()
    stack.dns.start.assert_called_once()
    stack.http.start.assert_awaited_once()
    assert stack._http_started is True


async def test_stop_tears_down_everything(mocker):
    stack = _stack(mocker)
    await stack.start()
    await stack.stop()
    stack.nat.stop.assert_called_once()
    stack.http.stop.assert_awaited_once()
    stack.dns.stop.assert_called_once()
    stack.bridge.stop.assert_called_once()
    assert stack._http_started is False


async def test_dns_failure_rolls_back_the_bridge_too(mocker):
    """A failure in a later stage must not leave an earlier one (the bridge/TAP) running."""
    stack = _stack(mocker)
    stack.dns.start.side_effect = RuntimeError("no cap_net_bind_service")
    try:
        await stack.start()
        raise AssertionError("expected the DNS failure to propagate")
    except RuntimeError:
        pass
    stack.bridge.stop.assert_called_once()             # rolled back, not left running
    stack.http.start.assert_not_awaited()               # never reached
    assert stack._http_started is False


async def test_http_failure_rolls_back_bridge_and_dns(mocker):
    stack = _stack(mocker)
    stack.http.start.side_effect = RuntimeError("port 80 in use")
    try:
        await stack.start()
        raise AssertionError("expected the HTTP failure to propagate")
    except RuntimeError:
        pass
    stack.dns.stop.assert_called_once()
    stack.bridge.stop.assert_called_once()
    assert stack._http_started is False
    stack.nat.start.assert_not_called()                  # never reached: core stack failed first


async def test_nat_is_attempted_after_the_core_stack_is_up(mocker):
    stack = _stack(mocker)
    await stack.start()
    stack.nat.start.assert_called_once()


async def test_nat_failure_does_not_fail_the_whole_stack(mocker):
    """Internet sharing is a bonus, not a requirement: no uplink (or a broken one) must not
    tear down an otherwise-working DHCP/DNS/HTTP portal."""
    stack = _stack(mocker)
    stack.nat.start.side_effect = RuntimeError("no internet-connected interface found to share")
    await stack.start()                                   # must not raise
    assert stack._http_started is True
    assert stack.nat_error == "no internet-connected interface found to share"


async def test_internet_shared_reflects_nat_uplink(mocker):
    stack = _stack(mocker)
    assert stack.internet_shared is False
    stack.nat.uplink = "wlan0"
    assert stack.internet_shared is True


async def test_stop_always_stops_nat_even_if_core_stack_never_started(mocker):
    stack = _stack(mocker)
    await stack.stop()                                    # never started; must not raise
    stack.nat.stop.assert_called_once()
