"""EvilTwin: a WPA2 twin that punts clients off a WPA3-transition AP and captures their 4-way.

``FakeAP`` (fake_ap.py) owns the twin's beacon, responder, and per-client state; the orchestrating
``EvilTwinCampaign`` (campaign.py) elects the two interfaces, runs the punt, and detects completion.
"""
from .fake_ap import FakeAP, FakeApStats, ClientProgress, ClientPhase
from .punter import Punter, PuntMode
from .campaign import (
    EvilTwinCampaign, EvilTwinInput, default_punt_modes, csa_target_channel,
)
from .presets import EvilTwinPreset, PresetPlan, PRESET_LABELS, PRESET_PLANS, eligible_presets
from wifit3.net.portal_templates import PortalTemplate

__all__ = ["FakeAP", "FakeApStats", "ClientProgress", "ClientPhase",
           "Punter", "PuntMode",
           "EvilTwinCampaign", "EvilTwinInput", "default_punt_modes", "csa_target_channel",
           "EvilTwinPreset", "PresetPlan", "PRESET_LABELS", "PRESET_PLANS", "eligible_presets",
           "PortalTemplate"]
