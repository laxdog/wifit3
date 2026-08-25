import os
import re
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select

from wifit3.chips.driver import FakeMacSupport
from wifit3.wlan.array import fake_mac_rank
from wifit3.ui.screens.focus_v2.art import display_name
from wifit3.campaigns.eviltwin import (
    EvilTwinInput, PuntMode, default_punt_modes, csa_target_channel,
    EvilTwinPreset, PRESET_LABELS, PRESET_PLANS, eligible_presets, PortalTemplate,
)

_PORTAL_TEMPLATES = [("WiFi password", PortalTemplate.PASSWORD.value),
                     ("Email + password login", PortalTemplate.LOGIN.value),
                     ("Click-through / terms agreement", PortalTemplate.CLICKTHROUGH.value)]

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

# (label, punt_period_sec, punt_once)
_CYCLES = [("Never", None, False), ("Once", 30.0, True), ("5 seconds", 5.0, False),
           ("10 seconds", 10.0, False), ("20 seconds", 20.0, False), ("30 seconds", 30.0, False),
           ("45 seconds", 45.0, False), ("60 seconds", 60.0, False)]
_DEFAULT_CYCLE = 5


def _plus_one(bssid: str) -> str:
    return bssid[:-1] + format((int(bssid[-1], 16) + 1) % 16, "x")


def _random_bssid() -> str:
    return "02:" + ":".join(f"{b:02x}" for b in os.urandom(5))


class EvilTwinInputModal(ModalScreen[Optional[EvilTwinInput]]):
    """Pick the twin/punter interfaces, BSSID, channel and punt method before EvilTwin starts."""

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    DEFAULT_CSS = """
    EvilTwinInputModal { align: center middle; }
    EvilTwinInputModal #dialog {
        width: 60; height: auto; max-height: 90%;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    EvilTwinInputModal #title { width: 1fr; content-align: center middle; margin-bottom: 1; text-style: bold; }
    EvilTwinInputModal .row { height: auto; margin-bottom: 0; }
    EvilTwinInputModal .row-label { width: 20; height: 3; content-align: left middle; color: $text-muted; }
    EvilTwinInputModal .row Select { width: 1fr; }
    EvilTwinInputModal #bssid-col { width: 1fr; height: auto; }
    EvilTwinInputModal #bssid-btns { height: auto; }
    EvilTwinInputModal #bssid-btns Button {   /* min-width set in app.py: App CSS outranks DEFAULT_CSS */
        width: auto; height: 1; border: none; padding: 0 1; margin-right: 2;
        background: $primary; color: auto;
    }
    EvilTwinInputModal #punt-methods { height: auto; margin: 0; }
    EvilTwinInputModal #punt-methods Checkbox { border: none; height: 1; padding: 0 1; background: transparent; }
    EvilTwinInputModal #warn { color: $text-warning; content-align: center middle; height: auto; display: none; }
    EvilTwinInputModal #button-row { height: auto; align: center middle; margin-top: 0; }
    EvilTwinInputModal #button-row Button { margin: 0 1; }
    """

    def __init__(self, target, members: List, clients: Optional[List] = None) -> None:
        super().__init__()
        self.target = target
        self._single = len(members) == 1     # one card: host + punt share the target's channel
        self._hosts = sorted((m for m in members if _can_host(m)), key=fake_mac_rank)
        self._punters = list(members)
        self._by_name = {m.name: m for m in members}
        self._clients = list(clients or [])  # clients associated to the target, for single-client mode
        self._presets = eligible_presets(target)

    def compose(self) -> ComposeResult:
        twin = self._hosts[0] if self._hosts else None
        punter = next((m for m in self._punters if m is not twin), twin)
        d_modes = default_punt_modes(self.target)
        pmf = self.target.pmf_required
        with Vertical(id="dialog"):
            yield Label("Evil Twin", id="title")

            with Horizontal(classes="row"):
                yield Label("Attack preset", classes="row-label")
                yield Select([(PRESET_LABELS[p], p.value) for p in self._presets],
                             value=self._presets[0].value, allow_blank=False, id="preset-select")

            with Horizontal(classes="row"):
                yield Label("EvilTwin interface", classes="row-label")
                yield Select([(display_name(m), m.name) for m in self._hosts],
                             value=twin.name if twin else Select.BLANK,
                             allow_blank=False, id="twin-iface")

            with Horizontal(classes="row"):
                yield Label("EvilTwin channel", classes="row-label")
                yield Select(self._channel_options(twin), value=self._default_channel(twin),
                             allow_blank=False, id="twin-channel", disabled=self._single)

            with Horizontal(classes="row"):
                yield Label("EvilTwin BSSID", classes="row-label")
                with Vertical(id="bssid-col"):
                    yield Input(value=self._default_bssid(), id="twin-bssid")
                    with Horizontal(id="bssid-btns"):
                        yield Button("Same", id="bssid-same")
                        yield Button("+1", id="bssid-plus1")
                        yield Button("Rand", id="bssid-random")

            with Horizontal(classes="row"):
                yield Label("Punter interface", classes="row-label")
                yield Select([(display_name(m), m.name) for m in self._punters],
                             value=punter.name if punter else Select.BLANK,
                             allow_blank=False, id="punt-iface")

            with Horizontal(classes="row"):
                yield Label("Target client", classes="row-label")
                yield Select([("All clients", "")] + [(c, c) for c in self._clients],
                             value="", allow_blank=False, id="target-client")

            if not self.target.akm_suites:               # open target: the IP layer is armed too
                with Horizontal(classes="row"):
                    yield Label("Portal page", classes="row-label")
                    yield Select(_PORTAL_TEMPLATES, value=PortalTemplate.PASSWORD.value,
                                 allow_blank=False, id="portal-template")
                if not self._single:                     # needs a spare radio to do the fetch on
                    yield Checkbox("Clone the real captive portal (needs 2 cards, adds delay)",
                                   value=False, id="clone-real-portal")

            with Vertical(id="punt-methods"):
                yield Checkbox("De-authenticate", value=PuntMode.DEAUTH in d_modes,
                               id="punt-deauth", disabled=pmf)
                yield Checkbox("Channel Switch Announcement", value=PuntMode.CSA in d_modes,
                               id="punt-csa")
                yield Checkbox("BSS-Transition Mode (BTM)", value=PuntMode.BTM in d_modes,
                               id="punt-btm", disabled=pmf)

            with Horizontal(classes="row"):
                yield Label("Punt cycle", classes="row-label")
                yield Select([(label, i) for i, (label, *_) in enumerate(_CYCLES)],
                             value=_DEFAULT_CYCLE, allow_blank=False, id="punt-cycle")

            yield Label("", id="warn")
            with Horizontal(id="button-row"):
                yield Button("Start EvilTwin", variant="primary", id="btn-start")
                yield Button("Cancel", variant="default", id="btn-cancel")

    def on_mount(self) -> None:
        self._sync_bssid_field()
        self._sync_warning()
        if self.target.pmf_required:                # robust-frame punts can't be forged under PMF
            self.query_one("#punt-deauth", Checkbox).tooltip = "Can't send deauths: PMF active"
            self.query_one("#punt-btm", Checkbox).tooltip = "Can't send BTMs: PMF active"

    # ----- interface / channel wiring ---------------------------------------

    def _channel_options(self, twin) -> List:
        if self._single:                        # locked to the target: one card can't host off-channel
            return [(self._channel_label(self.target.channel), self.target.channel)]
        chans = twin.supported_channels if twin else [self.target.channel]
        return [(self._channel_label(c), c) for c in chans]

    def _channel_label(self, channel: int) -> str:
        return f"{channel} (target)" if channel == self.target.channel else str(channel)

    def _default_channel(self, twin) -> int:
        if self._single:
            return self.target.channel
        chans = twin.supported_channels if twin else [self.target.channel]
        for c in (csa_target_channel(self.target.channel), self.target.channel):
            if c in chans:
                return c
        return chans[0]

    def _default_bssid(self) -> str:
        return _plus_one(self.target.bssid) if self._single else self.target.bssid

    def _selected(self, widget_id: str):
        return self._by_name.get(self.query_one(f"#{widget_id}", Select).value)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "twin-iface":
            twin = self._selected("twin-iface")
            channel = self.query_one("#twin-channel", Select)
            channel.set_options(self._channel_options(twin))
            channel.value = self._default_channel(twin)
            self._sync_bssid_field()
        elif event.select.id == "preset-select":
            self._apply_preset(EvilTwinPreset(event.value))
        self._sync_warning()

    # ----- presets -------------------------------------------------------------

    def _apply_preset(self, preset: EvilTwinPreset) -> None:
        """Fully recompute every widget this preset governs (never just apply overrides): a value
        left over from a prior preset must never survive the switch. Still editable by hand after."""
        plan = PRESET_PLANS[preset]
        twin = self._selected("twin-iface")

        if not self._single:
            punt_select = self.query_one("#punt-iface", Select)
            if plan.separate_punter is False:
                punt_select.value = twin.name if twin is not None else Select.BLANK
            else:                                        # True or None: prefer a distinct card
                other = next((m for m in self._punters if m is not twin), twin)
                punt_select.value = other.name if other else Select.BLANK

            channel_select = self.query_one("#twin-channel", Select)
            wanted = self.target.channel if plan.same_channel else self._default_channel(twin)
            options = [c for _, c in self._channel_options(twin)]
            if wanted in options:
                channel_select.value = wanted

        bssid = self.query_one("#twin-bssid", Input)
        if not bssid.disabled:
            mode = plan.bssid_mode or ("increment" if self._single else "same")
            bssid.value = (self.target.bssid if mode == "same" else _plus_one(self.target.bssid))

        modes = plan.punt_modes if plan.punt_modes is not None else default_punt_modes(self.target)
        checked = {"punt-deauth": (PuntMode.DEAUTH, PuntMode.DEAUTH_UNICAST),
                  "punt-csa": (PuntMode.CSA,), "punt-btm": (PuntMode.BTM,)}
        for bid, want in checked.items():
            cb = self.query_one(f"#{bid}", Checkbox)
            if not cb.disabled:
                cb.value = any(m in modes for m in want)

        default_cycle = (_CYCLES[_DEFAULT_CYCLE][1], _CYCLES[_DEFAULT_CYCLE][2])
        cycle = plan.cycle if plan.cycle is not None else default_cycle
        idx = next((i for i, (_, p, o) in enumerate(_CYCLES) if (p, o) == cycle), _DEFAULT_CYCLE)
        self.query_one("#punt-cycle", Select).value = idx

        target_client = self.query_one("#target-client", Select)
        if preset is EvilTwinPreset.TARGET_ONE_CLIENT and len(self._clients) == 1:
            target_client.value = self._clients[0]
        else:                                             # a stale single-client pick must not survive
            target_client.value = ""                      # a preset switch away from single-client mode

    def _sync_bssid_field(self) -> None:
        twin = self._selected("twin-iface")
        spoofable = twin is not None and twin.driver.FAKE_MAC is FakeMacSupport.SPOOFABLE
        bssid = self.query_one("#twin-bssid", Input)
        bssid.disabled = not spoofable
        for bid in ("bssid-same", "bssid-plus1", "bssid-random"):
            self.query_one(f"#{bid}", Button).disabled = not spoofable
        if not spoofable and twin is not None:
            bssid.value = twin.mac_address or self.target.bssid

    def _sync_warning(self) -> None:
        preset = EvilTwinPreset(self.query_one("#preset-select", Select).value)
        if preset is EvilTwinPreset.TARGET_ONE_CLIENT and not self.query_one("#target-client", Select).value:
            self._set_warn("Pick a target client below")
            return
        same_iface = self._selected("twin-iface") is self._selected("punt-iface")
        self._set_warn("EvilTwin works best with 2 different interfaces" if same_iface else "")

    def _set_warn(self, text: str) -> None:
        """Update the warning line and collapse it to zero rows when there's nothing to say."""
        warn = self.query_one("#warn", Label)
        warn.update(text)
        warn.display = bool(text)

    # ----- buttons -----------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        bssid = self.query_one("#twin-bssid", Input)
        if bid == "bssid-same":
            bssid.value = self.target.bssid
        elif bid == "bssid-plus1":
            bssid.value = _plus_one(self.target.bssid)
        elif bid == "bssid-random":
            bssid.value = _random_bssid()
        elif bid == "btn-start":
            self._start()
        elif bid == "btn-cancel":
            self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _start(self) -> None:
        twin = self._selected("twin-iface")
        punter = self._selected("punt-iface")
        channel = self.query_one("#twin-channel", Select).value
        twin_bssid = self.query_one("#twin-bssid", Input).value.strip().lower()
        if not _MAC_RE.match(twin_bssid):
            self._error("Invalid BSSID")
            return
        if twin_bssid == self.target.bssid and channel == self.target.channel:
            self._error("Same BSSID on the same channel collides; change one")
            return
        _, period, once = _CYCLES[self.query_one("#punt-cycle", Select).value]
        target_client = self.query_one("#target-client", Select).value or None
        open_target = not self.target.akm_suites
        template = (PortalTemplate(self.query_one("#portal-template", Select).value) if open_target
                   else PortalTemplate.PASSWORD)
        clone_real_portal = (open_target and not self._single
                            and self.query_one("#clone-real-portal", Checkbox).value)
        self.dismiss(EvilTwinInput(
            twin_iface=twin, punt_iface=punter, twin_channel=channel, twin_bssid=twin_bssid,
            punt_modes=self._punt_modes(target_client), csa_channel=None, punt_period_sec=period,
            punt_once=once, target_client=target_client,
            ip_layer=open_target, portal_template=template,   # open target: give clients a real IP
            clone_real_portal=clone_real_portal))

    def _punt_modes(self, target_client: Optional[str]) -> tuple[PuntMode, ...]:
        deauth_mode = PuntMode.DEAUTH_UNICAST if target_client else PuntMode.DEAUTH
        checked = {"punt-deauth": deauth_mode, "punt-csa": PuntMode.CSA, "punt-btm": PuntMode.BTM}
        return tuple(mode for bid, mode in checked.items()
                     if self.query_one(f"#{bid}", Checkbox).value)

    def _error(self, text: str) -> None:
        self._set_warn(f"[red]{text}[/red]")


def _can_host(iface) -> bool:
    return getattr(getattr(iface, "driver", None), "FAKE_MAC", None) in (
        FakeMacSupport.SPOOFABLE, FakeMacSupport.FIXED_MAC)
