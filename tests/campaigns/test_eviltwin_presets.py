"""EvilTwin presets: named knob bundles, filtered by target security posture."""
from types import SimpleNamespace

from wifit3.campaigns.eviltwin import EvilTwinPreset, PRESET_PLANS, eligible_presets


def test_secured_target_offers_downgrade_presets_not_open_clone():
    presets = eligible_presets(SimpleNamespace(akm_suites=[2]))
    assert EvilTwinPreset.WPA3_DOWNGRADE in presets
    assert EvilTwinPreset.PMF_SAFE_CSA in presets
    assert EvilTwinPreset.OPEN_CLONE not in presets


def test_open_target_offers_open_clone_not_downgrade_presets():
    presets = eligible_presets(SimpleNamespace(akm_suites=[]))
    assert EvilTwinPreset.OPEN_CLONE in presets
    assert EvilTwinPreset.WPA3_DOWNGRADE not in presets
    assert EvilTwinPreset.PMF_SAFE_CSA not in presets


def test_every_preset_has_a_plan():
    for preset in EvilTwinPreset:
        assert preset in PRESET_PLANS
