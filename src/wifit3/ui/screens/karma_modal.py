"""KarmaInputModal: pick the interface/channel/portal page before Karma mode starts. Unlike
``EvilTwinInputModal`` there is no target AP to derive anything from -- Karma answers whatever
SSID a nearby client asks for, so the only choices are which radio hosts it and which channel it
sits on.
"""
from __future__ import annotations

from typing import List, NamedTuple, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Select

from wifit3.chips.driver import FakeMacSupport
from wifit3.wlan.array import fake_mac_rank
from wifit3.ui.screens.focus_v2.art import display_name
from wifit3.net.portal_templates import PortalTemplate

_PORTAL_TEMPLATES = [("Click-through / terms agreement", PortalTemplate.CLICKTHROUGH.value),
                     ("WiFi password", PortalTemplate.PASSWORD.value),
                     ("Email + password login", PortalTemplate.LOGIN.value),
                     ("Access code / voucher", PortalTemplate.VOUCHER.value),
                     ("Phone number", PortalTemplate.PHONE.value),
                     ("Hotel room + last name", PortalTemplate.ROOM.value)]


def _can_host(iface) -> bool:
    return getattr(getattr(iface, "driver", None), "FAKE_MAC", None) in (
        FakeMacSupport.SPOOFABLE, FakeMacSupport.FIXED_MAC)


class KarmaInput(NamedTuple):
    iface: object
    channel: int
    portal_template: PortalTemplate


class KarmaInputModal(ModalScreen[Optional[KarmaInput]]):
    """Pick the interface, channel, and portal page before Karma mode starts."""

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    DEFAULT_CSS = """
    KarmaInputModal { align: center middle; }
    KarmaInputModal #dialog {
        width: 56; height: auto; border: thick $primary; background: $surface; padding: 1 2;
    }
    KarmaInputModal #title { width: 1fr; content-align: center middle; margin-bottom: 1; text-style: bold; }
    KarmaInputModal .row { height: auto; margin-bottom: 0; }
    KarmaInputModal .row-label { width: 18; height: 3; content-align: left middle; color: $text-muted; }
    KarmaInputModal .row Select { width: 1fr; }
    KarmaInputModal #button-row { height: auto; align: center middle; margin-top: 1; }
    KarmaInputModal #button-row Button { margin: 0 1; }
    """

    def __init__(self, members: List) -> None:
        super().__init__()
        self._hosts = sorted((m for m in members if _can_host(m)), key=fake_mac_rank)

    def compose(self) -> ComposeResult:
        iface = self._hosts[0] if self._hosts else None
        with Vertical(id="dialog"):
            yield Label("Karma Mode", id="title")
            with Horizontal(classes="row"):
                yield Label("Interface", classes="row-label")
                yield Select([(display_name(m), m.name) for m in self._hosts],
                             value=iface.name if iface else Select.BLANK,
                             allow_blank=False, id="karma-iface")
            with Horizontal(classes="row"):
                yield Label("Channel", classes="row-label")
                yield Select(self._channel_options(iface), value=self._default_channel(iface),
                             allow_blank=False, id="karma-channel")
            with Horizontal(classes="row"):
                yield Label("Portal page", classes="row-label")
                yield Select(_PORTAL_TEMPLATES, value=PortalTemplate.CLICKTHROUGH.value,
                             allow_blank=False, id="portal-template")
            with Horizontal(id="button-row"):
                yield Button("Start Karma", variant="primary", id="btn-start")
                yield Button("Cancel", variant="default", id="btn-cancel")

    # ----- interface / channel wiring ---------------------------------------

    def _channel_options(self, iface) -> List:
        chans = iface.supported_channels if iface else [1]
        return [(str(c), c) for c in chans]

    def _default_channel(self, iface) -> int:
        chans = iface.supported_channels if iface else [1]
        if iface is not None and iface.current_channel in chans:
            return iface.current_channel
        return chans[0]

    def _by_name(self, name) -> Optional[object]:
        return next((m for m in self._hosts if m.name == name), None)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "karma-iface":
            return
        iface = self._by_name(event.value)
        channel = self.query_one("#karma-channel", Select)
        channel.set_options(self._channel_options(iface))
        channel.value = self._default_channel(iface)

    # ----- buttons -------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self._start()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _start(self) -> None:
        iface = self._by_name(self.query_one("#karma-iface", Select).value)
        if iface is None:
            return
        channel = self.query_one("#karma-channel", Select).value
        template = PortalTemplate(self.query_one("#portal-template", Select).value)
        self.dismiss(KarmaInput(iface=iface, channel=channel, portal_template=template))
