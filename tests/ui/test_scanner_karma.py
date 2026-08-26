"""Karma mode's Scanner wiring: launch (pauses only the cards Karma actually uses), stop (resumes
just those cards), and the live poll that logs + persists probes/joins/submissions across
however many radios are in play. The modal itself (per-card checkboxes/channel pickers) is plain
Select/Checkbox/Button wiring and isn't driven here.
"""
from unittest.mock import Mock

import pytest

from wifit3.dot11.mac import str_to_mac
from wifit3.persist.save import SaveResult
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.karma_modal import KarmaInput
from wifit3.ui.screens.scanner import ScannerView
from wifit3.net.portal_templates import PortalTemplate

_ASSUMED_MAC_A = "02:11:22:33:44:55"
_ASSUMED_MAC_B = "02:66:77:88:99:aa"


class _FakeIface:
    def __init__(self, channel: int = 1, assumed_mac: str = _ASSUMED_MAC_A):
        self.sent: list = []
        self.current_channel = channel
        self.supported_channels = [1, 6, 11]
        self.assumed_mac = assumed_mac
        self.callbacks: list = []
        self.hop_started = 0
        self.hop_stopped = 0

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

    async def start_hopping(self, channels=None, interval=0.5) -> None:
        self.hop_started += 1

    async def stop_hopping(self) -> None:
        self.hop_stopped += 1


class _FakeArray:
    def __init__(self, members):
        self.members = members


async def _mounted_scanner(app) -> ScannerView:
    app.push_screen("scanner")
    return app.screen


@pytest.fixture(autouse=True)
def _no_real_ip_layer(mocker):
    """Unlike EvilTwin's opt-in checkbox, Karma always tries to bring up the IP layer -- never
    let these Scanner-level UI tests touch a real TAP/DHCP/iptables on the box running them."""
    stack = mocker.MagicMock(start=mocker.AsyncMock(), stop=mocker.AsyncMock())
    mocker.patch("wifit3.campaigns.karma.campaign.PortalStack", return_value=stack)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_karma_mode_with_no_array_logs_and_does_not_push_modal():
    app = WifiteApp()
    async with app.run_test() as pilot:
        scanner = await _mounted_scanner(app)
        await pilot.pause(0)
        app.array = None
        scanner.push_screen = Mock()
        scanner.action_karma_mode()
        scanner.push_screen.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_karma_mode_pushes_the_modal_when_an_array_is_present():
    app = WifiteApp()
    async with app.run_test() as pilot:
        scanner = await _mounted_scanner(app)
        await pilot.pause(0)
        app.array = _FakeArray([_FakeIface()])
        app.push_screen = Mock()
        scanner.action_karma_mode()
        app.push_screen.assert_called_once()
        from wifit3.ui.screens.karma_modal import KarmaInputModal
        assert isinstance(app.push_screen.call_args.args[0], KarmaInputModal)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_launch_pauses_only_the_chosen_cards_and_stop_resumes_them():
    app = WifiteApp()
    async with app.run_test() as pilot:
        scanner = await _mounted_scanner(app)
        await pilot.pause(0)
        used = _FakeIface(channel=1, assumed_mac=_ASSUMED_MAC_A)
        idle = _FakeIface(channel=1, assumed_mac=_ASSUMED_MAC_B)
        array = _FakeArray([used, idle])
        app.array = array

        result = KarmaInput(hosts=((used, 6),), portal_template=PortalTemplate.CLICKTHROUGH)
        await scanner._launch_karma(array, result)
        assert used.hop_stopped == 1 and idle.hop_stopped == 0    # only the chosen card pauses
        camp = scanner._karma_campaign
        assert camp is not None
        await pilot.pause(0.05)
        assert camp.karmas[0].bssid == str_to_mac(_ASSUMED_MAC_A)
        assert camp.karmas[0].on_rx in used.callbacks

        task = camp._task
        scanner._stop_karma()
        assert scanner._karma_campaign is None
        await task
        assert used.hop_started == 1 and idle.hop_started == 0    # idle card was never touched
        assert used.callbacks == []                                # unregistered on teardown


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_second_press_stops_a_running_campaign():
    app = WifiteApp()
    async with app.run_test() as pilot:
        scanner = await _mounted_scanner(app)
        await pilot.pause(0)
        iface = _FakeIface()
        array = _FakeArray([iface])
        app.array = array
        result = KarmaInput(hosts=((iface, 1),), portal_template=PortalTemplate.CLICKTHROUGH)
        await scanner._launch_karma(array, result)
        camp = scanner._karma_campaign
        assert camp is not None

        scanner.action_karma_mode()          # toggles off (no modal on the way out)
        assert scanner._karma_campaign is None
        await camp._task


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_poll_karma_merges_ssids_across_every_radio_and_persists_submissions(mocker):
    app = WifiteApp()
    async with app.run_test() as pilot:
        scanner = await _mounted_scanner(app)
        await pilot.pause(0)
        a = _FakeIface(channel=1, assumed_mac=_ASSUMED_MAC_A)
        b = _FakeIface(channel=1, assumed_mac=_ASSUMED_MAC_B)
        array = _FakeArray([a, b])
        app.array = array
        result = KarmaInput(hosts=((a, 1), (b, 6)), portal_template=PortalTemplate.CLICKTHROUGH)
        await scanner._launch_karma(array, result)
        await pilot.pause(0.05)

        logged: list = []
        scanner._write_log = lambda text: logged.append(str(text))
        save_mock = mocker.patch("wifit3.ui.screens.scanner.save_portal_credentials",
                                 return_value=SaveResult(path=__import__("pathlib").Path(
                                     "captures/Karma_02-11-22-33-44-55_1_portal.txt"), was_new=True))

        camp = scanner._karma_campaign
        camp.karmas[0].stats.ssids_seen.append("HomeWifi")
        camp.karmas[1].stats.ssids_seen.append("HomeWifi")     # same SSID seen on a 2nd radio too
        camp.karmas[1].stats.ssids_seen.append("Airport_Free_WiFi")
        camp.joined_clients.append({"mac": "02:aa:bb:cc:dd:ee", "ssid": "HomeWifi", "at": 0.0})
        camp.portal_submissions.append({"email": "a@b.com"})

        scanner._poll_karma()

        probed_lines = [line for line in logged if "probed for" in line]
        assert sum("HomeWifi" in line for line in probed_lines) == 1     # deduped across radios
        assert any("Airport_Free_WiFi" in line for line in probed_lines)
        assert any("client joined" in line for line in logged)
        assert any("portal credentials" in line for line in logged)
        save_mock.assert_called_once()
        called_ap = save_mock.call_args.args[0]
        assert called_ap.ssid == "Karma" and called_ap.bssid == _ASSUMED_MAC_A

        task = camp._task
        scanner._stop_karma()
        await task
