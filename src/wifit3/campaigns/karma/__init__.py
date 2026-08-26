"""Karma: an opportunistic open-network responder with no fixed target.

``KarmaAP`` (karma_ap.py) owns one radio's shared-BSSID responder + per-SSID/per-client state, one
instance per (interface, channel) pair; ``KarmaBridge`` (bridge.py) is the MAC-learning bridge
that lets clients on any of those radios share one TAP/subnet; the orchestrating
``KarmaCampaign`` (campaign.py) owns the radios and the same captive-portal IP layer EvilTwin's
open-clone uses.
"""
from .karma_ap import KarmaAP, KarmaApStats, KarmaClient
from .bridge import KarmaBridge
from .campaign import KarmaCampaign

__all__ = ["KarmaAP", "KarmaApStats", "KarmaClient", "KarmaBridge", "KarmaCampaign"]
