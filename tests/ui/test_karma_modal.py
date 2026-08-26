"""KarmaInputModal's pure helpers: channel auto-assignment and the host-collection logic, tested
without a running Textual app (same pattern as ``test_eviltwin_modal.py``)."""
from types import SimpleNamespace

from wifit3.ui.screens.karma_modal import _default_channels, _can_host
from wifit3.chips.driver import FakeMacSupport


def _iface(channels):
    return SimpleNamespace(supported_channels=channels)


def test_default_channels_prefers_the_non_overlapping_24ghz_trio():
    hosts = [_iface([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
             _iface([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
             _iface([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])]
    assert _default_channels(hosts) == [1, 6, 11]


def test_default_channels_gives_each_host_a_distinct_channel_where_possible():
    hosts = [_iface([1, 6, 11]), _iface([1, 6, 11])]
    channels = _default_channels(hosts)
    assert len(set(channels)) == 2


def test_default_channels_falls_back_to_repeating_when_a_host_has_no_unused_channel_left():
    # Only channel 1 supported by either -- the second host must repeat it, not crash.
    hosts = [_iface([1]), _iface([1])]
    assert _default_channels(hosts) == [1, 1]


def test_default_channels_respects_each_hosts_own_supported_set():
    # A 5GHz-capable card should get a 5GHz channel once 2.4GHz is exhausted by other hosts.
    hosts = [_iface([1, 6, 11]), _iface([1, 6, 11]), _iface([1, 6, 11]), _iface([1, 6, 11, 36])]
    channels = _default_channels(hosts)
    assert channels[3] == 36


def test_can_host_accepts_spoofable_and_fixed_mac_only():
    spoofable = SimpleNamespace(driver=SimpleNamespace(FAKE_MAC=FakeMacSupport.SPOOFABLE))
    fixed = SimpleNamespace(driver=SimpleNamespace(FAKE_MAC=FakeMacSupport.FIXED_MAC))
    none = SimpleNamespace(driver=SimpleNamespace(FAKE_MAC=FakeMacSupport.NONE))
    assert _can_host(spoofable) and _can_host(fixed) and not _can_host(none)
