"""PortalFetch: a one-shot client-role association to the real (open) target, used only to
retrieve whatever captive-portal HTML it actually serves, so the twin can show the real page
instead of a generic template. Runs before the twin arms, on the punt card (dual-card only --
there's no spare radio for this in single-card mode). Always best-effort: any failure at any
stage (no assoc, no DHCP, no portal, target unreachable) just means falling back to the generic
template afterward -- this never raises, and never blocks the twin from starting without it.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from wifit3.campaigns.auth_assoc import Association, build_client_leaving, random_client_mac
from wifit3.campaigns.eviltwin.client_bridge import ClientBridge
from wifit3.dot11 import str_to_mac
from wifit3.net.dhcp_client import request_lease
from wifit3.net.portal_http_client import fetch_portal_page

logger = logging.getLogger(__name__)

TAP_NAME = "wifit3fetch0"
_ASSOC_ATTEMPTS = 2
# DISCOVER is always broadcast, so it's never hardware-ACKed/retried at the 802.11 level like a
# unicast frame is -- a lost DISCOVER is just gone, no link-layer recovery. Confirmed live (two
# AR9271s over the air): occasional loss is normal, not a bug, so this retries more persistently
# than a wired DHCP client would need to.
_DHCP_TIMEOUT = 10.0
_DHCP_RETRIES = 5
_HTTP_TIMEOUT = 5.0
_OVERALL_TIMEOUT = 30.0


async def fetch_real_portal(array, iface, bssid: str, ssid: str, channel: int) -> Optional[str]:
    """Associate to the real target, DHCP, and fetch whatever it serves on port 80. None on any
    failure: always best-effort, so the caller just falls back to the generic template."""
    try:
        return await asyncio.wait_for(_fetch(array, iface, bssid, ssid, channel), _OVERALL_TIMEOUT)
    except Exception as exc:                                    # noqa: BLE001
        logger.info("eviltwin: real-portal fetch failed: %s", exc)
        return None


async def _fetch(array, iface, bssid: str, ssid: str, channel: int) -> Optional[str]:
    our_mac = random_client_mac()
    bssid_bytes = str_to_mac(bssid)
    async with array.lease(channel=channel, iface=iface) as leased:
        arm = array.lease(fake_mac=our_mac, bssid=bssid_bytes, iface=leased)
        async with arm:
            if arm.mac:
                our_mac = str_to_mac(arm.mac)
            return await _associate_and_fetch(leased, bssid_bytes, bssid, ssid, channel, our_mac)


async def _associate_and_fetch(iface, bssid_bytes: bytes, bssid: str, ssid: str, channel: int,
                               our_mac: bytes) -> Optional[str]:
    assoc = Association(iface, bssid, ssid, channel, our_mac=our_mac)
    assoc.start()
    try:
        if not await assoc.associate(attempts=_ASSOC_ATTEMPTS):
            logger.info("eviltwin: real-portal fetch: association failed (%s)", assoc.fail_reason)
            return None
        dhcp_frames: "asyncio.Queue[bytes]" = asyncio.Queue()
        bridge = ClientBridge(iface, bssid_bytes, our_mac, tap_name=TAP_NAME,
                              on_eth_frame=dhcp_frames.put_nowait)
        bridge.start()
        try:
            # _on_tap_frame (not tap.write!) is the transmit direction: it wraps an Ethernet
            # frame as 802.11 ToDS and injects it over the air, same as it does for the kernel's
            # own outbound traffic. tap.write() is the opposite direction (inject as received).
            # Replies come back via dhcp_frames (fed by on_eth_frame above), not a bound socket:
            # the TAP has no address yet, and a broadcast reply isn't kernel-delivered to a
            # socket on an addressless interface (confirmed live).
            lease = await request_lease(our_mac, bridge._on_tap_frame, dhcp_frames,
                                        timeout=_DHCP_TIMEOUT, retries=_DHCP_RETRIES)
            if lease is None or lease.router is None:
                logger.info("eviltwin: real-portal fetch: no DHCP lease from the target")
                return None
            bridge.tap.add_address(lease.ip, lease.prefix)
            return await fetch_portal_page(TAP_NAME, lease.router, timeout=_HTTP_TIMEOUT)
        finally:
            bridge.stop()
    finally:
        try:
            await iface.send_no_wait(build_client_leaving(bssid_bytes, our_mac))
        except Exception:                                       # noqa: BLE001
            pass
        assoc.stop()
