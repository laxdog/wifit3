"""EvilTwin attack presets: named bundles of the existing knobs (``EvilTwinInput`` fields), not a
new campaign or a locked mode. Picking one just prefills the modal's widgets; every field stays
editable after. ``eligible_presets`` narrows the list to what makes sense for the target's security
posture (RSN-downgrade presets are meaningless against an open network, and vice versa).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Optional

from wifit3.campaigns.eviltwin.punter import PuntMode


class EvilTwinPreset(enum.Enum):
    WPA3_DOWNGRADE = "wpa3_downgrade"
    PMF_SAFE_CSA = "pmf_safe_csa"
    OPEN_CLONE = "open_clone"
    PASSIVE = "passive"
    SAME_CHANNEL_SINGLE_CARD = "same_channel_single_card"
    OFF_CHANNEL_DUAL_CARD = "off_channel_dual_card"
    TARGET_ONE_CLIENT = "target_one_client"


PRESET_LABELS: dict[EvilTwinPreset, str] = {
    EvilTwinPreset.WPA3_DOWNGRADE: "WPA3 transition downgrade",
    EvilTwinPreset.PMF_SAFE_CSA: "PMF-safe CSA twin",
    EvilTwinPreset.OPEN_CLONE: "Open network clone",
    EvilTwinPreset.PASSIVE: "Passive twin / no punt",
    EvilTwinPreset.SAME_CHANNEL_SINGLE_CARD: "Same-channel single-card",
    EvilTwinPreset.OFF_CHANNEL_DUAL_CARD: "Off-channel dual-card",
    EvilTwinPreset.TARGET_ONE_CLIENT: "Target one client",
}


@dataclass(frozen=True)
class PresetPlan:
    """Every field a preset switch recomputes from scratch; ``None`` means the modal's own
    baseline default for that knob, not "leave whatever's there"."""
    same_channel: Optional[bool] = None        # True: force twin channel == target's; False/None: decoy
    separate_punter: Optional[bool] = None     # False: same card as twin; True/None: a distinct card
    bssid_mode: Optional[str] = None           # "same" | "increment"; None: the modal's single/dual default
    punt_modes: Optional[tuple[PuntMode, ...]] = None   # None = default_punt_modes(target)
    cycle: Optional[tuple[Optional[float], bool]] = None  # (punt_period_sec, punt_once); None = 5s default


_DEFAULT = PresetPlan()   # today's WPA2/WPA3-PSK downgrade behavior, unchanged

PRESET_PLANS: dict[EvilTwinPreset, PresetPlan] = {
    EvilTwinPreset.WPA3_DOWNGRADE: _DEFAULT,
    EvilTwinPreset.OPEN_CLONE: _DEFAULT,        # same knobs; FakeAP/campaign auto-detect open vs secured
    EvilTwinPreset.PMF_SAFE_CSA: PresetPlan(punt_modes=(PuntMode.CSA,)),
    EvilTwinPreset.PASSIVE: PresetPlan(punt_modes=(), cycle=(None, False)),
    # bssid_mode is forced "increment": same_channel=True already puts the twin on the target's own
    # channel, so a "same" BSSID there would collide with the real AP, not just resemble it.
    EvilTwinPreset.SAME_CHANNEL_SINGLE_CARD: PresetPlan(same_channel=True, separate_punter=False,
                                                        bssid_mode="increment"),
    EvilTwinPreset.OFF_CHANNEL_DUAL_CARD: PresetPlan(same_channel=False, separate_punter=True,
                                                      bssid_mode="same"),
    EvilTwinPreset.TARGET_ONE_CLIENT: PresetPlan(punt_modes=(PuntMode.DEAUTH_UNICAST, PuntMode.BTM)),
}

_OPEN_PRESETS = (EvilTwinPreset.OPEN_CLONE, EvilTwinPreset.PASSIVE,
                 EvilTwinPreset.SAME_CHANNEL_SINGLE_CARD, EvilTwinPreset.OFF_CHANNEL_DUAL_CARD,
                 EvilTwinPreset.TARGET_ONE_CLIENT)
_SECURED_PRESETS = (EvilTwinPreset.WPA3_DOWNGRADE, EvilTwinPreset.PMF_SAFE_CSA,
                    EvilTwinPreset.PASSIVE, EvilTwinPreset.SAME_CHANNEL_SINGLE_CARD,
                    EvilTwinPreset.OFF_CHANNEL_DUAL_CARD, EvilTwinPreset.TARGET_ONE_CLIENT)


def eligible_presets(ap) -> tuple[EvilTwinPreset, ...]:
    """Presets whose label makes sense for this target: ``OPEN_CLONE`` only with no RSN to
    downgrade; ``WPA3_DOWNGRADE`` only against a genuine WPA3-transition AP (SAE and PSK both)."""
    if not ap.akm_suites:
        return _OPEN_PRESETS
    if ap.wpa3 and ap.transition_mode:
        return _SECURED_PRESETS
    # WPA2-only or WPA3-only: no downgrade for the preset to name, and a client honoring
    # Transition-Disable would refuse the twin regardless.
    return tuple(p for p in _SECURED_PRESETS if p is not EvilTwinPreset.WPA3_DOWNGRADE)
