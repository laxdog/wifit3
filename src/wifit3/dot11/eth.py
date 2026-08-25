"""802.11 Data frame <-> raw Ethernet-II frame translation (pure spec, no I/O).

A TAP device speaks raw Ethernet-II (dst(6) + src(6) + ethertype(2) + payload); the wire speaks
802.11 Data frames with an LLC/SNAP (RFC 1042) header carrying the same ethertype. Generalizes
the encapsulation ``dot11/eapol.py`` already uses for EAPOL (ethertype 0x888E) to any ethertype,
so ARP/IPv4/IPv6 can cross the link too. Direction-agnostic: works for an AP-role twin bridging
its clients (``to_ds=False`` downlink, ToDS=1 uplink) and for a client-role association to a real
AP (the mirror image), since the wire format for a Data MPDU is identical either way, only the
address-field roles (Table 9-26, IEEE 802.11-2020) differ.
"""
from __future__ import annotations

from typing import Optional

LLC_SNAP_PREFIX = bytes.fromhex("aaaa03000000")   # SNAP header, OUI 000000 (RFC 1042), sans ethertype


def to_dot11(*, to_ds: bool = False, bssid: bytes, station: bytes, eth_frame: bytes) -> bytes:
    """Wrap a raw Ethernet-II frame as a Data MPDU. AP role (default): ``station`` is the client.
    Client role (``to_ds=True``): ``station`` is our MAC; addr3 carries the frame's real DA."""
    if len(eth_frame) < 14:
        raise ValueError(f"Ethernet frame too short: {len(eth_frame)} bytes")
    da, ethertype, payload = eth_frame[0:6], eth_frame[12:14], eth_frame[14:]
    if to_ds:
        header = bytes([0x08, 0x01]) + b"\x00\x00" + bssid + station + da + b"\x00\x00"
    else:
        header = bytes([0x08, 0x02]) + b"\x00\x00" + station + bssid + bssid + b"\x00\x00"
    return header + LLC_SNAP_PREFIX + ethertype + payload


def from_dot11(raw: bytes) -> Optional[bytes]:
    """An RX Data MPDU -> a raw Ethernet-II frame, or None if it isn't a bridgeable plain
    LLC/SNAP frame (protected, malformed, other OUI, or WDS/IBSS). Direction-agnostic."""
    if len(raw) < 24:
        return None
    fc0, fc1 = raw[0], raw[1]
    if fc1 & 0x40:                              # WEP/CCMP-protected: nothing to bridge
        return None
    to_ds, from_ds = bool(fc1 & 0x01), bool(fc1 & 0x02)
    if to_ds == from_ds:                         # both clear (IBSS) or both set (WDS): unhandled
        return None
    subtype = (fc0 & 0xF0) >> 4
    header_len = 24
    if subtype & 0x08:                          # QoS Control field present
        header_len += 2
    if fc1 & 0x80:                               # HT Control field present (Order bit)
        header_len += 4
    if len(raw) < header_len + 8 or raw[header_len:header_len + 6] != LLC_SNAP_PREFIX:
        return None
    if to_ds:                                     # STA->AP: addr1=BSSID, addr2=SA, addr3=DA
        sa, da = raw[10:16], raw[16:22]
    else:                                          # AP->STA: addr1=DA, addr2=BSSID, addr3=SA
        sa, da = raw[16:22], raw[4:10]
    ethertype = raw[header_len + 6:header_len + 8]
    payload = raw[header_len + 8:]
    return da + sa + ethertype + payload
