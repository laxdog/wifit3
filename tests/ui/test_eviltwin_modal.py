import re
from types import SimpleNamespace

from textual.app import App
from textual.widgets import Checkbox, Input, Select

from wifit3.chips.driver import FakeMacSupport
from wifit3.campaigns.eviltwin import EvilTwinPreset, PuntMode, PortalTemplate
from wifit3.ui.screens.focus_v2.eviltwin_modal import (
    EvilTwinInputModal, _plus_one, _random_bssid, _CYCLES,
)

_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _modal(single: bool, target) -> EvilTwinInputModal:
    m = object.__new__(EvilTwinInputModal)   # exercise the pure knob helpers without a Textual app
    m._single, m.target = single, target
    return m


def test_single_card_locks_channel_to_target_and_bumps_bssid():
    target = SimpleNamespace(channel=6, bssid="94:83:c4:8c:3f:78")
    m = _modal(True, target)
    assert m._default_channel(None) == 6
    assert m._channel_options(None) == [("6 (target)", 6)]
    assert m._default_bssid() == "94:83:c4:8c:3f:79"


def test_multi_card_keeps_decoy_channel_and_target_bssid():
    target = SimpleNamespace(channel=1, bssid="94:83:c4:8c:3f:78")
    m = _modal(False, target)
    twin = SimpleNamespace(supported_channels=[1, 6, 11])
    assert m._default_channel(twin) == 6                        # CSA decoy off ch 1
    assert m._channel_options(twin) == [("1 (target)", 1), ("6", 6), ("11", 11)]
    assert m._default_bssid() == "94:83:c4:8c:3f:78"


def test_plus_one_bumps_last_nibble():
    assert _plus_one("94:83:c4:8c:3f:78") == "94:83:c4:8c:3f:79"
    assert _plus_one("94:83:c4:8c:3f:7f") == "94:83:c4:8c:3f:70"   # wraps f -> 0


def test_random_bssid_is_locally_administered():
    b = _random_bssid()
    assert _MAC.match(b) and b.startswith("02:")


def test_cycle_table():
    by_label = {label: (period, once) for label, period, once in _CYCLES}
    assert by_label["Never"] == (None, False)
    assert by_label["Once"][1] is True
    assert by_label["30 seconds"] == (30.0, False)


# --- mounted widget: preset selection -----------------------------------------

def _mounted_iface(name: str, channels=(1, 6, 11)):
    return SimpleNamespace(name=name, product_name=name, chipset=name,
                           driver=SimpleNamespace(FAKE_MAC=FakeMacSupport.SPOOFABLE, product_name=name),
                           supported_channels=list(channels), mac_address="02:11:22:33:44:55")


def _mounted_target(channel=1, bssid="94:83:c4:8c:3f:78", akm_suites=(2,), pmf_required=False):
    return SimpleNamespace(channel=channel, bssid=bssid, akm_suites=list(akm_suites),
                           pmf_required=pmf_required)


async def test_off_channel_dual_card_preset_picks_a_distinct_punter_and_spoofs_the_bssid():
    a, b = _mounted_iface("Card A"), _mounted_iface("Card B")
    target = _mounted_target()
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a, b]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        # Start from a state the preset must actively correct, not one it happens to match already.
        modal.query_one("#punt-iface", Select).value = "Card A"
        modal.query_one("#twin-bssid", Input).value = "00:11:22:33:44:55"
        await pilot.pause()

        modal.query_one("#preset-select", Select).value = EvilTwinPreset.OFF_CHANNEL_DUAL_CARD.value
        await pilot.pause()
        assert modal.query_one("#twin-iface", Select).value != modal.query_one("#punt-iface", Select).value
        assert modal.query_one("#twin-bssid", Input).value == target.bssid


async def test_same_channel_single_card_preset_forces_twin_and_punt_onto_one_card():
    a, b = _mounted_iface("Card A"), _mounted_iface("Card B")
    target = _mounted_target()
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a, b]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        assert modal.query_one("#twin-channel", Select).value != target.channel   # starts on the decoy
        assert modal.query_one("#punt-iface", Select).value == "Card B"           # starts on the other card

        modal.query_one("#preset-select", Select).value = EvilTwinPreset.SAME_CHANNEL_SINGLE_CARD.value
        await pilot.pause()
        assert modal.query_one("#twin-channel", Select).value == target.channel
        assert modal.query_one("#twin-iface", Select).value == modal.query_one("#punt-iface", Select).value


async def test_target_one_client_preset_autoselects_the_lone_client_and_goes_unicast():
    a = _mounted_iface("Card A")
    target = _mounted_target()
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a], ["02:aa:bb:cc:dd:ee"]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        modal.query_one("#preset-select", Select).value = EvilTwinPreset.TARGET_ONE_CLIENT.value
        await pilot.pause()
        assert modal.query_one("#target-client", Select).value == "02:aa:bb:cc:dd:ee"

        await pilot.click("#btn-start")
        await pilot.pause()

    assert result and result[0] is not None
    out = result[0]
    assert out.target_client == "02:aa:bb:cc:dd:ee"
    assert PuntMode.DEAUTH_UNICAST in out.punt_modes
    assert out.ip_layer is False                      # secured target: no IP layer to bring up


async def test_open_target_offers_open_clone_preset_not_downgrade_presets():
    a = _mounted_iface("Card A")
    target = _mounted_target(akm_suites=())
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        assert EvilTwinPreset.OPEN_CLONE in modal._presets
        assert EvilTwinPreset.WPA3_DOWNGRADE not in modal._presets


async def test_open_target_start_requests_the_ip_layer():
    a = _mounted_iface("Card A")
    target = _mounted_target(akm_suites=())
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        await pilot.click("#btn-start")
        await pilot.pause()

    assert result and result[0] is not None
    assert result[0].ip_layer is True                  # open target: give the client a real IP
    assert result[0].portal_template is PortalTemplate.PASSWORD   # default choice


async def test_open_target_portal_template_choice_flows_through():
    a = _mounted_iface("Card A")
    target = _mounted_target(akm_suites=())
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        modal.query_one("#portal-template", Select).value = PortalTemplate.LOGIN.value
        await pilot.pause()
        await pilot.click("#btn-start")
        await pilot.pause()

    assert result and result[0].portal_template is PortalTemplate.LOGIN


async def test_secured_target_portal_template_row_hidden_until_forced_open():
    a = _mounted_iface("Card A")
    target = _mounted_target()                          # secured by default (akm_suites=(2,))
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        assert modal.query_one("#portal-template-row").display is False
        await pilot.click("#btn-start")
        await pilot.pause()

    assert result and result[0].ip_layer is False
    assert result[0].force_open is False


async def test_secured_target_force_open_reveals_portal_row_and_flows_through():
    a, b = _mounted_iface("Card A"), _mounted_iface("Card B")
    target = _mounted_target()                          # secured (akm_suites=(2,))
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a, b]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        modal.query_one("#force-open", Checkbox).value = True
        await pilot.pause()
        assert modal.query_one("#portal-template-row").display is True
        assert modal.query_one("#clone-real-portal", Checkbox).display is True
        modal.query_one("#portal-template", Select).value = PortalTemplate.LOGIN.value
        await pilot.pause()
        await pilot.click("#btn-start")
        await pilot.pause()

    assert result and result[0] is not None
    assert result[0].force_open is True
    assert result[0].ip_layer is True
    assert result[0].portal_template is PortalTemplate.LOGIN


async def test_open_target_has_no_force_open_checkbox():
    a = _mounted_iface("Card A")
    target = _mounted_target(akm_suites=())
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        assert len(modal.query("#force-open")) == 0


async def test_single_card_open_target_has_no_clone_checkbox():
    a = _mounted_iface("Card A")
    target = _mounted_target(akm_suites=())
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        assert len(modal.query("#clone-real-portal")) == 0    # no spare radio for the fetch
        await pilot.click("#btn-start")
        await pilot.pause()

    assert result and result[0].clone_real_portal is False


async def test_dual_card_open_target_clone_checkbox_flows_through():
    a, b = _mounted_iface("Card A"), _mounted_iface("Card B")
    target = _mounted_target(akm_suites=())
    result = []

    class _Host(App):
        def on_mount(self) -> None:
            self.push_screen(EvilTwinInputModal(target, [a, b]), result.append)

    async with _Host().run_test(size=(100, 50)) as pilot:
        await pilot.pause()
        modal = pilot.app.screen
        modal.query_one("#clone-real-portal", Checkbox).value = True
        await pilot.pause()
        await pilot.click("#btn-start")
        await pilot.pause()

    assert result and result[0].clone_real_portal is True
