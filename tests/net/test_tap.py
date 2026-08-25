"""TapDevice.add_address: the ``ip`` invocations it makes (mocked out -- pure OS integration,
same as the rest of tap.py's subprocess calls; no real TAP device touched)."""
from wifit3.net.tap import TapDevice


def _tap(mocker) -> TapDevice:
    tap = TapDevice("wifit3fetch0")
    mocker.patch("wifit3.net.tap._run")
    return tap


def test_add_address_without_gateway_only_sets_the_address(mocker):
    tap = _tap(mocker)
    tap.add_address("10.13.37.100", 24)
    from wifit3.net.tap import _run
    _run.assert_called_once_with("wifit3fetch0", "addr", "add", "10.13.37.100/24",
                                 "dev", "wifit3fetch0")


def test_add_address_with_gateway_also_adds_a_low_priority_default_route(mocker):
    """The route must carry a high metric so it's never preferred over the host's own real
    default route for ordinary (non-SO_BINDTODEVICE-scoped) traffic."""
    tap = _tap(mocker)
    tap.add_address("10.13.37.100", 24, gateway="10.13.37.1")
    from wifit3.net.tap import _run
    assert _run.call_count == 2
    addr_call, route_call = _run.call_args_list
    assert addr_call.args == ("wifit3fetch0", "addr", "add", "10.13.37.100/24",
                              "dev", "wifit3fetch0")
    assert route_call.args == ("wifit3fetch0", "route", "add", "default", "via", "10.13.37.1",
                               "dev", "wifit3fetch0", "metric", "20000")
