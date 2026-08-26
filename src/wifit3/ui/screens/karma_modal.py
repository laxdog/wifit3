"""KarmaInputModal: pick which cards host Karma, each on its own channel, and the portal page.
Unlike ``EvilTwinInputModal`` there is no target AP to derive anything from -- Karma answers
whatever SSID a nearby client asks for, so the only choices are which radios take part (one per
channel: a client's probe only reaches Karma if it's on the channel Karma is actually sitting on)
and which page joiners see.
"""
from __future__ import annotations

from typing import List, NamedTuple, Optional, Tuple

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Label, Select

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

# Preference order for auto-assigning distinct channels across the checked cards: the
# non-overlapping 2.4GHz trio first (where most saved-network probing happens), then the rest.
_PREFERRED_CHANNELS = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 36, 40, 44, 48, 149, 153, 157, 161]


def _can_host(iface) -> bool:
    return getattr(getattr(iface, "driver", None), "FAKE_MAC", None) in (
        FakeMacSupport.SPOOFABLE, FakeMacSupport.FIXED_MAC)


def _default_channels(hosts: List) -> List[int]:
    """One distinct channel per host where possible; a host only repeats a channel already given
    to another host when it has no unused channel of its own left to try."""
    used: set = set()
    out: List[int] = []
    for host in hosts:
        supported = host.supported_channels or [1]
        pick = next((c for c in _PREFERRED_CHANNELS if c in supported and c not in used), None)
        if pick is None:
            pick = next((c for c in supported if c not in used), None)
        if pick is None:
            pick = supported[0]
        used.add(pick)
        out.append(pick)
    return out


class KarmaInput(NamedTuple):
    hosts: Tuple[Tuple[object, int], ...]     # ((iface, channel), ...), at least one
    portal_template: PortalTemplate


class KarmaInputModal(ModalScreen[Optional[KarmaInput]]):
    """Pick which cards host Karma (each its own channel) and the portal page."""

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    DEFAULT_CSS = """
    KarmaInputModal { align: center middle; }
    KarmaInputModal #dialog {
        width: 56; height: auto; max-height: 90%; border: thick $primary; background: $surface; padding: 1 2;
    }
    KarmaInputModal #title { width: 1fr; content-align: center middle; margin-bottom: 1; text-style: bold; }
    KarmaInputModal .row { height: auto; margin-bottom: 0; }
    KarmaInputModal .row-label { width: 18; height: 3; content-align: left middle; color: $text-muted; }
    KarmaInputModal .row Select { width: 1fr; }
    KarmaInputModal .card-row { height: 3; }
    KarmaInputModal .card-row Checkbox { width: 1fr; border: none; }
    KarmaInputModal .card-row Select { width: 12; }
    KarmaInputModal #warn { color: $text-warning; content-align: center middle; height: auto; display: none; }
    KarmaInputModal #button-row { height: auto; align: center middle; margin-top: 1; }
    KarmaInputModal #button-row Button { margin: 0 1; }
    """

    def __init__(self, members: List) -> None:
        super().__init__()
        self._hosts = sorted((m for m in members if _can_host(m)), key=fake_mac_rank)
        self._defaults = _default_channels(self._hosts)

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Karma Mode", id="title")
            with Vertical(id="card-rows"):
                for i, iface in enumerate(self._hosts):
                    with Horizontal(classes="row card-row"):
                        yield Checkbox(display_name(iface), value=True, id=f"card-{i}")
                        yield Select(self._channel_options(iface), value=self._defaults[i],
                                     allow_blank=False, id=f"channel-{i}")
            with Horizontal(classes="row"):
                yield Label("Portal page", classes="row-label")
                yield Select(_PORTAL_TEMPLATES, value=PortalTemplate.CLICKTHROUGH.value,
                             allow_blank=False, id="portal-template")
            yield Label("", id="warn")
            with Horizontal(id="button-row"):
                yield Button("Start Karma", variant="primary", id="btn-start")
                yield Button("Cancel", variant="default", id="btn-cancel")

    def on_mount(self) -> None:
        self._sync_warning()

    # ----- interface / channel wiring ---------------------------------------

    def _channel_options(self, iface) -> List:
        return [(str(c), c) for c in (iface.supported_channels or [1])]

    def _checked_hosts(self) -> List[Tuple[object, int]]:
        out = []
        for i, iface in enumerate(self._hosts):
            if self.query_one(f"#card-{i}", Checkbox).value:
                channel = self.query_one(f"#channel-{i}", Select).value
                out.append((iface, channel))
        return out

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        self._sync_warning()

    def _sync_warning(self) -> None:
        if not self._checked_hosts():
            self._set_warn("Pick at least one card")
        else:
            self._set_warn("")

    def _set_warn(self, text: str) -> None:
        warn = self.query_one("#warn", Label)
        warn.update(text)
        warn.display = bool(text)

    # ----- buttons -------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self._start()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _start(self) -> None:
        hosts = self._checked_hosts()
        if not hosts:
            self._sync_warning()
            return
        template = PortalTemplate(self.query_one("#portal-template", Select).value)
        self.dismiss(KarmaInput(hosts=tuple(hosts), portal_template=template))
