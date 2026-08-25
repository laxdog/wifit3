"""KarmaCampaign: drives KarmaAP on one operator-picked interface, no target AP, reuses
EvilTwin's PortalStack for the IP layer exactly like an open-clone twin does.
"""
import asyncio

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.karma import KarmaCampaign
from wifit3.dot11.mac import str_to_mac

_ASSUMED_MAC = "02:11:22:33:44:55"


class _FakeIface:
    def __init__(self, channel: int = 1):
        self.sent: list[bytes] = []
        self.current_channel = channel
        self.callbacks: list = []

    async def send_no_wait(self, frame: bytes) -> bool:
        self.sent.append(frame)
        return True

    async def set_channel(self, channel: int, scan: bool = False) -> bool:
        self.current_channel = channel
        return True

    async def set_fake_mac(self, mac=None, bssid=None):
        return _ASSUMED_MAC

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


def test_iface_property_is_the_operator_pick_not_select_iface():
    """No target AP exists to derive a channel from, so unlike every other campaign this must
    not go through ``Campaign.select_iface``."""
    iface = _FakeIface()
    camp = KarmaCampaign(array=None, iface=iface, channel=6)
    assert camp.iface is iface
    assert isinstance(camp, Campaign) and camp.ap is None


async def test_loop_starts_karma_on_the_requested_channel_and_registers_rx():
    iface = _FakeIface(channel=1)
    camp = KarmaCampaign(array=None, iface=iface, channel=6)
    task = await _run_briefly(camp)
    assert iface.current_channel == 6
    assert camp.karma.bssid == str_to_mac(_ASSUMED_MAC)
    assert camp.karma.on_rx in iface.callbacks
    await _stop(camp, task)
    assert iface.callbacks == []                       # unregistered on teardown


async def test_client_joined_is_recorded():
    iface = _FakeIface()
    camp = KarmaCampaign(array=None, iface=iface, channel=1)
    task = await _run_briefly(camp)
    camp._on_client_joined("02:aa:bb:cc:dd:ee", "HomeWifi")
    assert camp.joined_clients == [{"mac": "02:aa:bb:cc:dd:ee", "ssid": "HomeWifi",
                                    "at": camp.joined_clients[0]["at"]}]
    await _stop(camp, task)


async def test_ip_layer_starts_when_karma_starts_and_stops_on_teardown(mocker):
    stack = mocker.MagicMock(start=mocker.AsyncMock(), stop=mocker.AsyncMock())
    mocker.patch("wifit3.campaigns.karma.campaign.PortalStack", return_value=stack)
    camp = KarmaCampaign(array=None, iface=_FakeIface(), channel=1)
    task = await _run_briefly(camp)
    assert camp.portal is stack and camp.ip_layer_error is None
    stack.start.assert_awaited_once()
    await _stop(camp, task)
    stack.stop.assert_awaited_once()


async def test_ip_layer_failure_degrades_gracefully(mocker):
    failing = mocker.MagicMock(start=mocker.AsyncMock(side_effect=RuntimeError("no tun")))
    mocker.patch("wifit3.campaigns.karma.campaign.PortalStack", return_value=failing)
    camp = KarmaCampaign(array=None, iface=_FakeIface(), channel=1)
    task = await _run_briefly(camp)
    assert camp.portal is None and camp.ip_layer_error == "no tun"
    assert not task.done()                              # still running despite the failure
    await _stop(camp, task)
