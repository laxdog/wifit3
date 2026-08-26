"""Karma mode's Scanner wiring: launch (pauses the hopper, starts KarmaCampaign), stop (resumes
the hopper), and the live poll that logs + persists probes/joins/submissions. The modal itself
(interface/channel/portal-page pickers) is plain Select/Button wiring and isn't driven here.
"""
from unittest.mock import Mock

import pytest

from wifit3.dot11.mac import str_to_mac
from wifit3.persist.save import SaveResult
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.karma_modal import KarmaInput
from wifit3.ui.screens.scanner import ScannerView
from wifit3.net.portal_templates import PortalTemplate

_ASSUMED_MAC = "02:11:22:33:44:55"


class _FakeIface:
    def __init__(self, channel: int = 1):
        self.sent: list = []
        self.current_channel = channel
        self.supported_channels = [1, 6, 11]
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


class _FakeArray:
    def __init__(self, members):
        self.members = members
        self.stop_calls = 0
        self.start_calls = 0

    async def stop_hopping(self) -> None:
        self.stop_calls += 1

    async def start_hopping(self, channels=None, interval=0.25) -> None:
        self.start_calls += 1


async def _mounted_scanner(app) -> ScannerView:
    app.push_screen("scanner")
    return app.screen


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
async def test_launch_then_stop_pauses_and_resumes_the_hopper():
    app = WifiteApp()
    async with app.run_test() as pilot:
        scanner = await _mounted_scanner(app)
        await pilot.pause(0)
        iface = _FakeIface(channel=1)
        array = _FakeArray([iface])
        app.array = array

        result = KarmaInput(iface=iface, channel=6, portal_template=PortalTemplate.CLICKTHROUGH)
        await scanner._launch_karma(array, result)
        assert array.stop_calls == 1
        camp = scanner._karma_campaign
        assert camp is not None
        await pilot.pause(0.05)
        assert camp.karma is not None and camp.karma.bssid == str_to_mac(_ASSUMED_MAC)
        assert camp.karma.on_rx in iface.callbacks

        scanner._stop_karma()
        assert scanner._karma_campaign is None
        await camp._task                                     # deterministically await teardown
        assert array.start_calls == 1
        assert iface.callbacks == []                        # unregistered on teardown


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
        result = KarmaInput(iface=iface, channel=1, portal_template=PortalTemplate.CLICKTHROUGH)
        await scanner._launch_karma(array, result)
        camp = scanner._karma_campaign
        assert camp is not None

        scanner.action_karma_mode()          # toggles off (no modal on the way out)
        assert scanner._karma_campaign is None
        await camp._task


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_poll_karma_logs_ssids_joins_and_persists_submissions(mocker):
    app = WifiteApp()
    async with app.run_test() as pilot:
        scanner = await _mounted_scanner(app)
        await pilot.pause(0)
        iface = _FakeIface()
        array = _FakeArray([iface])
        app.array = array
        result = KarmaInput(iface=iface, channel=1, portal_template=PortalTemplate.CLICKTHROUGH)
        await scanner._launch_karma(array, result)
        await pilot.pause(0.05)

        logged: list = []
        scanner._write_log = lambda text: logged.append(str(text))
        save_mock = mocker.patch("wifit3.ui.screens.scanner.save_portal_credentials",
                                 return_value=SaveResult(path=__import__("pathlib").Path(
                                     "captures/Karma_02-11-22-33-44-55_1_portal.txt"), was_new=True))

        camp = scanner._karma_campaign
        camp.karma.stats.ssids_seen.append("HomeWifi")
        camp.joined_clients.append({"mac": "02:aa:bb:cc:dd:ee", "ssid": "HomeWifi", "at": 0.0})
        camp.portal_submissions.append({"email": "a@b.com"})

        scanner._poll_karma()

        assert any("HomeWifi" in line and "probed for" in line for line in logged)
        assert any("client joined" in line for line in logged)
        assert any("portal credentials" in line for line in logged)
        save_mock.assert_called_once()
        called_ap = save_mock.call_args.args[0]
        assert called_ap.ssid == "Karma" and called_ap.bssid == _ASSUMED_MAC

        task = camp._task
        scanner._stop_karma()
        await task
