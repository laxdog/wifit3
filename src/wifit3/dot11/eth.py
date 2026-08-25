"""802.11 Data frame <-> raw Ethernet-II frame translation (pure spec, no I/O).

A TAP device speaks raw Ethernet-II (dst(6) + src(6) + ethertype(2) + payload); the wire speaks
802.11 Data frames with an LLC/SNAP (RFC 1042) header carrying the same ethertype. Generalizes
the encapsulation ``dot11/eapol.py`` already uses for EAPOL (ethertype 0x888E) to any ethertype,
so ARP/IPv4/IPv6 can cross the link too.
"""
from __future__ import annotations

from typing import Optional

from wifit3.dot11.eapol import data_header

LLC_SNAP_PREFIX = bytes.fromhex("aaaa03000000")   # SNAP header, OUI 000000 (RFC 1042), sans ethertype


def to_dot11(*, bssid: bytes, client: bytes, eth_frame: bytes) -> bytes:
    """AP->client (FromDS): wrap a raw Ethernet-II frame from the TAP as a Data MPDU. The TAP's
    own MAC must equal ``bssid`` (set at bring-up) so addr3/SA stays consistent."""
    if len(eth_frame) < 14:
        raise ValueError(f"Ethernet frame too short: {len(eth_frame)} bytes")
    ethertype, payload = eth_frame[12:14], eth_frame[14:]
    return data_header(to_ds=False, bssid=bssid, client=client) + LLC_SNAP_PREFIX + ethertype + payload


def from_dot11(raw: bytes) -> Optional[bytes]:
    """Client->AP (ToDS): an RX Data MPDU -> a raw Ethernet-II frame, or None if it isn't a
    bridgeable plain LLC/SNAP (RFC 1042) frame (protected, malformed, other SNAP OUI)."""
    if len(raw) < 24:
        return None
    fc0, fc1 = raw[0], raw[1]
    if fc1 & 0x40:                              # WEP/CCMP-protected: nothing to bridge
        return None
    subtype = (fc0 & 0xF0) >> 4
    header_len = 24
    if subtype & 0x08:                          # QoS Control field present
        header_len += 2
    if fc1 & 0x80:                               # HT Control field present (Order bit)
        header_len += 4
    if len(raw) < header_len + 8 or raw[header_len:header_len + 6] != LLC_SNAP_PREFIX:
        return None
    sa, da = raw[10:16], raw[16:22]              # ToDS: addr2 = SA (client), addr3 = DA
    ethertype = raw[header_len + 6:header_len + 8]
    payload = raw[header_len + 8:]
    return da + sa + ethertype + payload
