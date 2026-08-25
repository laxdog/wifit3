"""FocusViewV2 must surface EvilTwin's open-twin IP-layer events live, while the campaign is
still running (an open twin may never auto-stop on its own): a client joining, and each
captive-portal form submission, both logged and the latter persisted to captures/."""
import pytest
from textual.app import App
from textual.widgets import RichLog

from wifit3.ui.screens.focus_v2 import FocusViewV2
from wifit3.ui.screens.focus_v2.log_band import LogBand
from wifit3.wlan.interface import WlanInterface
from wifit3.wlan.sink import WlanSink

from tests.frames import pkt


@pytest.fixture(autouse=True)
def _isolate_captures_dir(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)


class MockDriver:
    async def set_channel(self, ch, scan=False):
        return True

    def register_rx_callback(self, cb):
        pass

    def register_disconnect_callback(self, cb):
        pass


def _beacon(bssid, ssid, ch):
    return pkt({
        "type": "beacon", "bssid": bssid, "ssid": ssid, "channel": ch,
        "rssi": -40, "encryption": "OPEN", "akms": [], "akm_suites": [],
        "pairwise_cipher": None, "raw": b"\xff-beacon-raw",
    })


class _FakeArray:
    """One-card WlanArray for the UI (mirrors test_focus_v2_capture.py's fixture)."""
    def __init__(self, iface):
        self._iface = iface
        self._sink = WlanSink()
        iface.on_tx = self._sink.record_tx
        iface.register_rx_callback(lambda pkt: self._sink.update(pkt, iface.name))

    @property
    def members(self):
        return [self._iface]

    def select_iface(self, channel):
        return self._iface

    def get_access_points(self):
        return self._sink.get_access_points()

    async def set_channel(self, ch, scan=False):
        if self._iface.current_channel == ch:
            return True
        return await self._iface.set_channel(ch, scan=scan)

    async def stop_hopping(self):
        return await self._iface.stop_hopping()

    async def start_hopping(self, channels=None, interval=0.5):
        return await self._iface.start_hopping(channels, interval)

    def __getattr__(self, name):
        return getattr(self._sink, name)


class _Host(App):
    def __init__(self, array, ap):
        super().__init__()
        self.array = array
        self.target_ap = ap
        self.pbc_enabled = True

    def on_mount(self) -> None:
        self.push_screen(FocusViewV2())


class _FakeEvilTwin:
    """Just enough of EvilTwinCampaign's public surface for `_tick`'s teardown/status/live-event
    checks to run without crashing: client_joined, portal_submissions, ap, done, and the
    attributes ``derive_headline``/``derive_buttons`` read off it."""
    def __init__(self, ap):
        self.ap = ap
        self.client_joined = False
        self.portal_submissions: list[dict] = []
        self.captured = False
        self.ip_layer_error = None
        self.twin_channel = 6
        self.fakeap = None
        self.done = False
        self.fetching_real_portal = False
        self.cloned_real_portal = False
        self.portal_fetch_status = None


def _log_text(band: LogBand) -> str:
    rich = band.query_one("#log-rich", RichLog)
    return "\n".join(strip.text for strip in rich.lines)


def _open_target(bssid="94:83:c4:8c:3f:78", ssid="TESTNET", ch=6):
    iface = WlanInterface(MockDriver(), "wlanX", "Mock card")
    array = _FakeArray(iface)
    iface._on_frame_parsed(_beacon(bssid, ssid, ch))
    return iface, array, array.access_points[bssid]


async def test_client_join_logged_live_exactly_once():
    iface, array, ap = _open_target()
    app = _Host(array, ap)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        focus = app.screen
        focus._tick_timer.stop()
        focus._target_ap = ap
        camp = _FakeEvilTwin(ap)
        focus._eviltwin_attack = camp

        focus._tick()
        await pilot.pause(0)
        camp.client_joined = True
        focus._tick()
        focus._tick()                          # a second tick must not double-log
        await pilot.pause(0)

        band = focus.query_one(LogBand)
        text = _log_text(band)
        assert text.count("A client joined the open twin") == 1


async def test_portal_submission_logged_and_saved():
    iface, array, ap = _open_target()
    app = _Host(array, ap)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        focus = app.screen
        focus._tick_timer.stop()
        focus._target_ap = ap
        camp = _FakeEvilTwin(ap)
        focus._eviltwin_attack = camp

        focus._tick()
        camp.portal_submissions.append({"password": "hunter2"})
        focus._tick()
        await pilot.pause(0)

        band = focus.query_one(LogBand)
        text = _log_text(band)
        assert "portal credentials" in text and "password=hunter2" in text
        assert "captures/" in text

    from pathlib import Path
    saved = list(Path("captures").glob("*_portal.txt"))
    assert len(saved) == 1
    assert "password: hunter2" in saved[0].read_text()


async def test_real_portal_clone_success_logged_live():
    iface, array, ap = _open_target()
    app = _Host(array, ap)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        focus = app.screen
        focus._tick_timer.stop()
        focus._target_ap = ap
        camp = _FakeEvilTwin(ap)
        focus._eviltwin_attack = camp

        camp.fetching_real_portal = True
        focus._tick()
        await pilot.pause(0)
        band = focus.query_one(LogBand)
        assert "cloning the real captive portal" in _log_text(band)

        camp.fetching_real_portal = False
        camp.cloned_real_portal = True
        camp.portal_fetch_status = "fetched from the gateway (868 bytes)"
        focus._tick()
        focus._tick()                          # a second tick must not double-log
        await pilot.pause(0)

        text = _log_text(band)
        assert text.count("fetched from the gateway (868 bytes)") == 1


async def test_real_portal_clone_failure_logged_live_with_reason():
    iface, array, ap = _open_target()
    app = _Host(array, ap)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        focus = app.screen
        focus._tick_timer.stop()
        focus._target_ap = ap
        camp = _FakeEvilTwin(ap)
        focus._eviltwin_attack = camp

        camp.fetching_real_portal = True
        focus._tick()
        camp.fetching_real_portal = False
        camp.cloned_real_portal = False
        camp.portal_fetch_status = "no DHCP lease from the target"
        focus._tick()
        await pilot.pause(0)

        band = focus.query_one(LogBand)
        text = _log_text(band)
        assert "no DHCP lease from the target" in text
        assert "falling back to the template" in text


async def test_multiple_submissions_each_logged_once():
    iface, array, ap = _open_target()
    app = _Host(array, ap)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0)
        focus = app.screen
        focus._tick_timer.stop()
        focus._target_ap = ap
        camp = _FakeEvilTwin(ap)
        focus._eviltwin_attack = camp

        focus._tick()
        camp.portal_submissions.append({"password": "wrong-guess"})
        focus._tick()
        camp.portal_submissions.append({"password": "hunter2"})
        focus._tick()
        focus._tick()                          # no new submissions: no new log lines
        await pilot.pause(0)

        band = focus.query_one(LogBand)
        text = _log_text(band)
        assert text.count("portal credentials") == 2
        assert "password=wrong-guess" in text and "password=hunter2" in text
