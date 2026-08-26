"""KarmaBridge: gives clients associated to ANY of Karma's radios a real IP over one shared TAP.

Unlike ``eviltwin.bridge.IpBridge`` (one fixed ``(iface, bssid)`` pair), Karma may run one radio
per channel, each with its own independently-forged bssid (the active-monitor mechanism can only
HW-ACK one forged address per physical card) -- but there's still only one TAP/subnet/portal
behind all of them. A downlink reply has to go out on whichever specific radio that client
actually associated through, stamped with that radio's own bssid, or it's a frame from a BSSID
the client never saw, on a channel it isn't listening on. This learns ``client_mac -> (iface,
bssid)`` from uplink traffic, exactly like an ordinary L2 switch, and floods every radio for
genuine broadcast (DHCP/ARP before a mapping exists).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Callable, Dict, List, Tuple

from wifit3.campaigns.eviltwin.bridge import POOL_START, PREFIX, SERVER_IP
from wifit3.dot11.eth import from_dot11, to_dot11
from wifit3.net.dhcp import DhcpServer
from wifit3.net.tap import TapDevice

logger = logging.getLogger(__name__)

_BROADCAST = b"\xff\xff\xff\xff\xff\xff"


class KarmaBridge:
    def __init__(self, cards: List[Tuple[object, bytes]], tap_name: str = "wifit3tap0"):
        if not cards:
            raise ValueError("KarmaBridge needs at least one (iface, bssid) pair")
        self.cards = list(cards)
        self.tap = TapDevice(tap_name)
        self.dhcp = DhcpServer(tap_name, server_ip=SERVER_IP, pool_start=POOL_START, prefix=PREFIX)
        self._client_card: Dict[bytes, Tuple[object, bytes]] = {}
        self._callbacks: List[Tuple[object, Callable]] = []
        self._running = False

    def start(self) -> None:
        """Raises ``TapPermissionError`` / ``RuntimeError`` on failure, after rolling back
        anything already opened: a failed attempt must never leak a TAP device."""
        # The TAP's own link-layer address never goes out over the air (every real per-packet
        # frame carries the correct originating radio's own bssid), so any one of the radios'
        # addresses works as well as another for it.
        _, tap_mac = self.cards[0]
        self.tap.open(mac=tap_mac, ip=SERVER_IP, prefix=PREFIX)
        try:
            self.tap.start_reading(self._on_tap_frame)
            self.dhcp.start()
            for iface, bssid in self.cards:
                cb = self._make_on_rx(iface, bssid)
                self._callbacks.append((iface, cb))
                iface.register_rx_callback(cb)
        except Exception:
            self.stop()                         # rolls back whatever of the above did succeed
            raise
        self._running = True

    def stop(self) -> None:
        self._running = False
        for iface, cb in self._callbacks:
            iface.unregister_rx_callback(cb)
        self._callbacks = []
        self.dhcp.stop()
        self.tap.close()

    def _make_on_rx(self, iface, bssid: bytes) -> Callable:
        """RX callback for one radio: Data frames addressed to *its own* bssid only (mgmt/EAPOL
        stay that radio's KarmaAP's job); learns the sender as reachable via ``(iface, bssid)``."""
        def _on_rx(pkt) -> None:
            if not self._running or pkt.type != "data":
                return
            raw = pkt.raw
            if len(raw) < 22 or not (raw[1] & 0x01) or raw[4:10] != bssid:
                return                                       # not an uplink frame addressed to us
            eth = from_dot11(raw)
            if eth is None:
                return
            self._client_card[eth[6:12]] = (iface, bssid)    # Ethernet SA = the client
            self.tap.write(eth)
        return _on_rx

    def _on_tap_frame(self, eth_frame: bytes) -> None:
        if not self._running or len(eth_frame) < 14:
            return
        dst = eth_frame[0:6]
        for iface, bssid in self._targets_for(dst):
            frame = to_dot11(bssid=bssid, station=dst, eth_frame=eth_frame)
            asyncio.create_task(iface.send_no_wait(frame))

    def _targets_for(self, dst: bytes) -> List[Tuple[object, bytes]]:
        if dst == _BROADCAST or dst not in self._client_card:
            return self.cards                    # broadcast, or not yet learned: flood every radio
        return [self._client_card[dst]]
