"""EvilTwin presets: named knob bundles, filtered by target security posture."""
from types import SimpleNamespace

from wifit3.campaigns.eviltwin import EvilTwinPreset, PRESET_PLANS, eligible_presets


def _ap(*, akm_suites, wpa3=False, transition_mode=False) -> SimpleNamespace:
    return SimpleNamespace(akm_suites=akm_suites, wpa3=wpa3, transition_mode=transition_mode)


def test_transition_target_offers_downgrade_and_csa_presets_not_open_clone():
    presets = eligible_presets(_ap(akm_suites=[2], wpa3=True, transition_mode=True))
    assert EvilTwinPreset.WPA3_DOWNGRADE in presets
    assert EvilTwinPreset.PMF_SAFE_CSA in presets
    assert EvilTwinPreset.OPEN_CLONE not in presets


def test_wpa2_only_target_offers_csa_but_not_downgrade():
    """WPA3_DOWNGRADE names downgrading a client away from SAE; a WPA2-only AP never offered
    SAE in the first place, so the preset is meaningless here even though it's still secured."""
    presets = eligible_presets(_ap(akm_suites=[2]))
    assert EvilTwinPreset.PMF_SAFE_CSA in presets
    assert EvilTwinPreset.WPA3_DOWNGRADE not in presets


def test_wpa3_only_non_transition_target_offers_csa_but_not_downgrade():
    """A WPA3-only AP with no PSK AKM has no client saved as PSK-tolerant, and a Transition-
    Disable-aware client would refuse the twin outright -- same exclusion as WPA2-only."""
    presets = eligible_presets(_ap(akm_suites=[8], wpa3=True, transition_mode=False))
    assert EvilTwinPreset.PMF_SAFE_CSA in presets
    assert EvilTwinPreset.WPA3_DOWNGRADE not in presets


def test_open_target_offers_open_clone_not_downgrade_presets():
    presets = eligible_presets(_ap(akm_suites=[]))
    assert EvilTwinPreset.OPEN_CLONE in presets
    assert EvilTwinPreset.WPA3_DOWNGRADE not in presets
    assert EvilTwinPreset.PMF_SAFE_CSA not in presets


def test_every_preset_has_a_plan():
    for preset in EvilTwinPreset:
        assert preset in PRESET_PLANS
