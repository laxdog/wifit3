"""IpBridge: gives clients associated to the open twin a real IP. Bridges the twin's uplink/
downlink Data-frame traffic to a TapDevice, and runs a DhcpServer behind it; the kernel's own IP
stack (routing, ARP) takes it from there. Optional and Linux-only for now: EvilTwinCampaign
degrades to today's association-only behavior when this can't come up (see ``ip_layer_error``).
"""
from __future__ import annotations

import asyncio
import logging

from wifit3.dot11.eth import from_dot11, to_dot11
from wifit3.net.dhcp import DhcpServer
from wifit3.net.tap import TapDevice

logger = logging.getLogger(__name__)

SERVER_IP = "10.13.37.1"
POOL_START = "10.13.37.100"
PREFIX = 24
SUBNET = "10.13.37.0/24"


class IpBridge:
    def __init__(self, twin_iface, bssid: bytes, tap_name: str = "wifit3tap0", rx_source=None):
        self.iface = twin_iface
        self.bssid = bssid
        self.rx_source = rx_source if rx_source is not None else twin_iface
        self.tap = TapDevice(tap_name)
        self.dhcp = DhcpServer(tap_name, server_ip=SERVER_IP, pool_start=POOL_START, prefix=PREFIX)
        self._running = False

    def start(self) -> None:
        """Raises ``TapPermissionError`` / ``RuntimeError`` on failure, after rolling back
        anything already opened: a failed attempt must never leak a TAP device."""
        self.tap.open(mac=self.bssid, ip=SERVER_IP, prefix=PREFIX)
        try:
            self.tap.start_reading(self._on_tap_frame)
            self.dhcp.start()
            self.rx_source.register_rx_callback(self.on_rx)
        except Exception:
            self.stop()                         # rolls back whatever of the above did succeed
            raise
        self._running = True

    def stop(self) -> None:
        self._running = False
        self.rx_source.unregister_rx_callback(self.on_rx)
        self.dhcp.stop()
        self.tap.close()

    def on_rx(self, pkt) -> None:
        """RX callback for the twin interface: Data frames only (mgmt/EAPOL stay FakeAP's job)."""
        if not self._running or pkt.type != "data":
            return
        raw = pkt.raw
        if len(raw) < 22 or not (raw[1] & 0x01) or raw[4:10] != self.bssid:
            return                                       # not an uplink frame addressed to us
        eth = from_dot11(raw)
        if eth is not None:
            self.tap.write(eth)

    def _on_tap_frame(self, eth_frame: bytes) -> None:
        if not self._running or len(eth_frame) < 14:
            return
        client = eth_frame[0:6]                            # Ethernet dst; ff:ff:.. -> 802.11 broadcast
        frame = to_dot11(bssid=self.bssid, station=client, eth_frame=eth_frame)
        asyncio.create_task(self.iface.send_no_wait(frame))
