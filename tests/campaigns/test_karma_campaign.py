"""KarmaCampaign: drives one KarmaAP per (interface, channel) pair, no target AP, reuses
EvilTwin's PortalStack via a KarmaBridge for the IP layer exactly like an open-clone twin does.
"""
import asyncio

import pytest

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.karma import KarmaCampaign

_ASSUMED_MAC_A = "02:11:22:33:44:55"
_ASSUMED_MAC_B = "02:66:77:88:99:aa"


@pytest.fixture(autouse=True)
def _no_real_ip_layer(mocker):
    """Karma always tries to bring up the IP layer unconditionally (no EvilTwin-style opt-in
    checkbox) -- never let a test that doesn't specifically need a real one touch a real
    TAP/DHCP/iptables on the box running it. Tests that DO care about the IP layer re-patch this
    themselves with a more specific mock/assertion; layering is harmless (last patch wins)."""
    stack = mocker.MagicMock(start=mocker.AsyncMock(), stop=mocker.AsyncMock())
    mocker.patch("wifit3.campaigns.karma.campaign.PortalStack", return_value=stack)


class _FakeIface:
    def __init__(self, channel: int = 1, assumed_mac=_ASSUMED_MAC_A):
        self.sent: list[bytes] = []
        self.current_channel = channel
        self.assumed_mac = assumed_mac
        self.callbacks: list = []

    async def send_no_wait(self, frame: bytes) -> bool:
        self.sent.append(frame)
        return True

    async def set_channel(self, channel: int, scan: bool = False) -> bool:
        self.current_channel = channel
        return True

    async def set_fake_mac(self, mac=None, bssid=None):
        return self.assumed_mac

    async def clear_fake_mac(self) -> None:
        pass

    def register_rx_callback(self, cb) -> None:
        self.callbacks.append(cb)

    def unregister_rx_callback(self, cb) -> None:
        self.callbacks.remove(cb)


async def _run_briefly(camp: KarmaCampaign) -> asyncio.Task:
    task = asyncio.create_task(camp._loop())
    await asyncio.sleep(0.05)
    return task


async def _stop(camp: KarmaCampaign, task: asyncio.Task) -> None:
    camp.stopped = True
    await task
    await camp.teardown()


def test_empty_hosts_rejected():
    with pytest.raises(ValueError):
        KarmaCampaign(array=None, hosts=[])


def test_is_a_normal_radio_owning_campaign_with_no_target_ap():
    camp = KarmaCampaign(array=None, hosts=[(_FakeIface(), 6)])
    assert isinstance(camp, Campaign) and camp.ap is None


async def test_loop_starts_one_karma_per_host_on_its_own_channel():
    a, b = _FakeIface(channel=1, assumed_mac=_ASSUMED_MAC_A), _FakeIface(channel=1, assumed_mac=_ASSUMED_MAC_B)
    camp = KarmaCampaign(array=None, hosts=[(a, 6), (b, 11)])
    task = await _run_briefly(camp)
    assert len(camp.karmas) == 2
    assert a.current_channel == 6 and b.current_channel == 11
    assert camp.karmas[0].iface is a and camp.karmas[1].iface is b
    assert camp.karmas[0].on_rx in a.callbacks
    await _stop(camp, task)


async def test_client_joined_is_recorded():
    camp = KarmaCampaign(array=None, hosts=[(_FakeIface(), 1)])
    task = await _run_briefly(camp)
    camp._on_client_joined("02:aa:bb:cc:dd:ee", "HomeWifi")
    assert camp.joined_clients == [{"mac": "02:aa:bb:cc:dd:ee", "ssid": "HomeWifi",
                                    "at": camp.joined_clients[0]["at"]}]
    await _stop(camp, task)


async def test_ip_layer_starts_with_a_bridge_across_every_host_and_stops_on_teardown(mocker):
    stack = mocker.MagicMock(start=mocker.AsyncMock(), stop=mocker.AsyncMock())
    portal_stack_cls = mocker.patch("wifit3.campaigns.karma.campaign.PortalStack", return_value=stack)
    a, b = _FakeIface(assumed_mac=_ASSUMED_MAC_A), _FakeIface(assumed_mac=_ASSUMED_MAC_B)
    camp = KarmaCampaign(array=None, hosts=[(a, 1), (b, 6)])
    task = await _run_briefly(camp)
    assert camp.portal is stack and camp.ip_layer_error is None
    stack.start.assert_awaited_once()
    bridge = portal_stack_cls.call_args.kwargs["bridge"]
    assert {iface for iface, _ in bridge.cards} == {a, b}
    await _stop(camp, task)
    stack.stop.assert_awaited_once()


async def test_ip_layer_failure_degrades_gracefully(mocker):
    failing = mocker.MagicMock(start=mocker.AsyncMock(side_effect=RuntimeError("no tun")))
    mocker.patch("wifit3.campaigns.karma.campaign.PortalStack", return_value=failing)
    camp = KarmaCampaign(array=None, hosts=[(_FakeIface(), 1)])
    task = await _run_briefly(camp)
    assert camp.portal is None and camp.ip_layer_error == "no tun"
    assert not task.done()                              # still running despite the failure
    await _stop(camp, task)
