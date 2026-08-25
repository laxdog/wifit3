"""PortalFetch: a one-shot client-role association to the real (open) target, used only to
retrieve whatever captive-portal HTML it actually serves, so the twin can show the real page
instead of a generic template. Runs before the twin arms, on the punt card (dual-card only --
there's no spare radio for this in single-card mode). Always best-effort: any failure at any
stage (no assoc, no DHCP, no portal, target unreachable) just means falling back to the generic
template afterward -- this never raises, and never blocks the twin from starting without it.

``FetchResult.status`` is always set (success or failure) with a specific, human-readable reason:
surfaced live in the UI log (``screen.py``) so a failed clone attempt says *why*, not just that it
failed -- association vs. DHCP vs. an unreachable/HTTPS-only portal are very different problems.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from wifit3.campaigns.auth_assoc import Association, build_client_leaving, random_client_mac
from wifit3.campaigns.eviltwin.client_bridge import ClientBridge
from wifit3.dot11 import str_to_mac
from wifit3.net.dhcp_client import DhcpLease, request_lease
from wifit3.net.dns_client import resolve as resolve_dns
from wifit3.net.portal_http_client import fetch_page_with_assets

logger = logging.getLogger(__name__)

TAP_NAME = "wifit3fetch0"
_ASSOC_ATTEMPTS = 2
# DISCOVER is always broadcast, so it's never hardware-ACKed/retried at the 802.11 level like a
# unicast frame is -- a lost DISCOVER is just gone, no link-layer recovery. Confirmed live (two
# AR9271s over the air): occasional loss is normal, not a bug, so this retries more persistently
# than a wired DHCP client would need to.
_DHCP_TIMEOUT = 10.0
_DHCP_RETRIES = 5
# A lightweight embedded router's splash server can be slow to respond, especially mid-redirect;
# 5s was too tight for that in practice. _OVERALL_TIMEOUT below is the real backstop regardless.
_HTTP_TIMEOUT = 8.0
# Must comfortably exceed the sum of everything it wraps, or a real (imperfect-RF, slightly slow)
# target gets cut off by this watchdog before finishing, even though every step would eventually
# succeed on its own: worst case is ~10s assoc + ~20s DHCP (DISCOVER + REQUEST phases, each up to
# _DHCP_TIMEOUT) + up to _MAX_REDIRECTS hops of the gateway fetch (DNS + connect + request, each
# up to _HTTP_TIMEOUT) + the same again for the probe-host fallback. 30s was tighter than that
# sum -- confirmed by reasoning through it, not just guessed -- so real-world fetches could time
# out here even when every individual step was actually working.
_OVERALL_TIMEOUT = 75.0

# Not every captive portal listens on its own gateway IP -- some (cloud-hosted controllers,
# transparent proxies) only intercept traffic bound elsewhere. Apple's own probe URL is what a
# real device hits to find one; if a real portal is present, it intercepts this exactly like it
# would intercept anything else, and we land on it instead of Apple's own page.
_PROBE_HOST = "captive.apple.com"
_PROBE_PATH = "/hotspot-detect.html"
_NOT_CAPTIVE_MARKER = "<BODY>Success</BODY>"   # the literal, un-intercepted Apple response


@dataclass
class FetchResult:
    page: Optional[str]
    status: str     # always set: the specific outcome, success or failure
    # path -> (content-type, body) for the page's own local <img>/<link>/<script> references
    # (icons/css/images), fetched alongside it so a served clone isn't full of broken links.
    assets: Dict[str, Tuple[str, bytes]] = field(default_factory=dict)


async def fetch_real_portal(array, iface, bssid: str, ssid: str, channel: int) -> FetchResult:
    """Associate, DHCP, and fetch whatever the target serves on port 80. ``page`` is None on any
    failure (best-effort: falls back to a template); ``status`` always says what happened."""
    try:
        return await asyncio.wait_for(_fetch(array, iface, bssid, ssid, channel), _OVERALL_TIMEOUT)
    except asyncio.TimeoutError:
        status = f"timed out after {_OVERALL_TIMEOUT:.0f}s"
        logger.info("eviltwin: real-portal fetch: %s", status)
        return FetchResult(None, status)
    except Exception as exc:                                    # noqa: BLE001
        logger.info("eviltwin: real-portal fetch failed: %s", exc)
        return FetchResult(None, f"unexpected error: {exc}")


async def _fetch(array, iface, bssid: str, ssid: str, channel: int) -> FetchResult:
    our_mac = random_client_mac()
    bssid_bytes = str_to_mac(bssid)
    async with array.lease(channel=channel, iface=iface) as leased:
        arm = array.lease(fake_mac=our_mac, bssid=bssid_bytes, iface=leased)
        async with arm:
            if arm.mac:
                our_mac = str_to_mac(arm.mac)
            return await _associate_and_fetch(leased, bssid_bytes, bssid, ssid, channel, our_mac)


async def _associate_and_fetch(iface, bssid_bytes: bytes, bssid: str, ssid: str, channel: int,
                               our_mac: bytes) -> FetchResult:
    assoc = Association(iface, bssid, ssid, channel, our_mac=our_mac)
    assoc.start()
    try:
        logger.info("eviltwin: real-portal fetch: associating to %s on ch %d", bssid, channel)
        if not await assoc.associate(attempts=_ASSOC_ATTEMPTS):
            status = f"association failed ({assoc.fail_reason or 'no response'})"
            logger.info("eviltwin: real-portal fetch: %s", status)
            return FetchResult(None, status)
        logger.info("eviltwin: real-portal fetch: associated, requesting a DHCP lease")
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
                status = "no DHCP lease from the target"
                logger.info("eviltwin: real-portal fetch: %s", status)
                return FetchResult(None, status)
            logger.info("eviltwin: real-portal fetch: got lease %s via %s, fetching the portal",
                       lease.ip, lease.router)
            bridge.tap.add_address(lease.ip, lease.prefix, gateway=lease.router)
            return await _fetch_page(lease)
        finally:
            bridge.stop()
    finally:
        try:
            await iface.send_no_wait(build_client_leaving(bssid_bytes, our_mac))
        except Exception:                                       # noqa: BLE001
            pass
        assoc.stop()


async def _fetch_page(lease: DhcpLease) -> FetchResult:
    """The gateway first (many portals listen there directly); if that comes back empty and we
    have a DNS server, fall back to the probe-host approach a real device would use."""
    page, assets = await fetch_page_with_assets(TAP_NAME, lease.router, dns_ip=lease.dns,
                                                timeout=_HTTP_TIMEOUT)
    if page is not None:
        status = f"fetched from the gateway ({len(page)} bytes, {len(assets)} asset(s))"
        logger.info("eviltwin: real-portal fetch: %s", status)
        return FetchResult(page, status, assets)
    if lease.dns is None:
        status = "gateway had nothing to serve, and no DNS server to try the probe-host fallback"
        logger.info("eviltwin: real-portal fetch: %s", status)
        return FetchResult(None, status)
    logger.info("eviltwin: real-portal fetch: gateway had nothing, trying %s%s",
               _PROBE_HOST, _PROBE_PATH)
    probe_ip = await resolve_dns(TAP_NAME, lease.dns, _PROBE_HOST, timeout=_HTTP_TIMEOUT)
    if probe_ip is None:
        status = f"gateway had nothing, and couldn't resolve {_PROBE_HOST} to try the fallback"
        logger.info("eviltwin: real-portal fetch: %s", status)
        return FetchResult(None, status)
    page, assets = await fetch_page_with_assets(TAP_NAME, probe_ip, dns_ip=lease.dns,
                                                path=_PROBE_PATH, timeout=_HTTP_TIMEOUT)
    if page is not None and _NOT_CAPTIVE_MARKER in page:
        status = "target has real internet (no captive portal to clone)"
        logger.info("eviltwin: real-portal fetch: %s", status)
        return FetchResult(None, status)
    if page is not None:
        status = f"fetched via the probe-host fallback ({len(page)} bytes, {len(assets)} asset(s))"
        logger.info("eviltwin: real-portal fetch: %s", status)
        return FetchResult(page, status, assets)
    status = "gateway and the probe-host fallback both failed (HTTPS-only portal?)"
    logger.info("eviltwin: real-portal fetch: %s", status)
    return FetchResult(None, status)
