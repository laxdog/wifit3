"""ClientBridge: bridges 802.11 Data-frame traffic for a client-role association (us, associated
to a real AP) to a TAP device -- the mirror image of ``bridge.py:IpBridge``'s AP-role bridging.
Used only by the one-shot real-portal fetch: gets DHCP and a normal socket connect working over
the association, so the target's actual captive-portal page can be retrieved.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Callable, Optional

from wifit3.dot11.eth import from_dot11, to_dot11
from wifit3.net.tap import TapDevice

logger = logging.getLogger(__name__)

_BROADCAST = b"\xff\xff\xff\xff\xff\xff"


class ClientBridge:
    def __init__(self, iface, bssid: bytes, our_mac: bytes, tap_name: str = "wifit3fetch0",
                on_eth_frame: Optional[Callable[[bytes], None]] = None):
        # on_eth_frame: fed every decoded downlink frame in addition to the TAP write, for a
        # caller (the DHCP client) that needs replies before the TAP has an address -- a normal
        # socket can't receive a broadcast reply on an addressless interface (confirmed live).
        self.iface = iface
        self.bssid = bssid
        self.our_mac = our_mac
        self.tap = TapDevice(tap_name)
        self.on_eth_frame = on_eth_frame
        self._running = False

    def start(self) -> None:
        """Raises ``TapPermissionError`` / ``RuntimeError`` on failure; no IP yet (that's what
        DHCP is for) -- just the interface, its MAC, and link up."""
        self.tap.open(mac=self.our_mac)
        self.tap.start_reading(self._on_tap_frame)
        self.iface.register_rx_callback(self.on_rx)
        self._running = True

    def stop(self) -> None:
        self._running = False
        self.iface.unregister_rx_callback(self.on_rx)
        self.tap.close()

    def on_rx(self, pkt) -> None:
        """Data frames from the real AP (FromDS), addressed to us OR broadcast (DHCP replies go
        to broadcast: we have no IP yet for the server to unicast to)."""
        if not self._running or pkt.type != "data":
            return
        raw = pkt.raw
        if len(raw) < 22 or not (raw[1] & 0x02) or raw[10:16] != self.bssid:
            return                                       # not a downlink frame from our AP
        addr1 = raw[4:10]
        if addr1 != self.our_mac and addr1 != _BROADCAST:
            return                                       # addressed to neither us nor everyone
        eth = from_dot11(raw)
        if eth is not None:
            self.tap.write(eth)
            if self.on_eth_frame is not None:
                self.on_eth_frame(eth)

    def _on_tap_frame(self, eth_frame: bytes) -> None:
        if not self._running or len(eth_frame) < 14:
            return
        frame = to_dot11(to_ds=True, bssid=self.bssid, station=self.our_mac, eth_frame=eth_frame)
        asyncio.create_task(self.iface.send_no_wait(frame))
