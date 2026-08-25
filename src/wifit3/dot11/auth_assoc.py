"""802.11 Open-System Authentication + Association Request builders (pure spec).

The frame bytes only; the stateful auth+assoc exchange (retries, RX matching) lives in
the campaign that drives these, ``campaigns.auth_assoc``.
"""
import struct

from wifit3.dot11.ie import ssid_ie, rates_ie, ext_rates_ie

# Assoc-request capability bits: ESS always, Privacy only when the target actually uses one
# (WEP/WPA/WPA2/WPA3 -- anything from Open System auth through a real handshake). Distinct from
# the probe-response capability (see dot11.probe._CAPABILITY_INFO). Do not conflate.
_CAP_ESS = 0x0001
_CAP_PRIVACY = 0x0010


def _hdr(fc: bytes, bssid: bytes, our_mac: bytes) -> bytes:
    """24-byte management header for a client->AP frame: addr1 = addr3 = bssid, addr2 =
    our forged STA. Duration and sequence are 0 (the chip fills the sequence)."""
    return fc + b"\x00\x00" + bssid + our_mac + bssid + b"\x00\x00"


def auth_req(bssid: bytes, our_mac: bytes) -> bytes:
    """Open-System Authentication Request (algorithm 0, sequence 1, status 0)."""
    return _hdr(b"\xb0\x00", bssid, our_mac) + b"\x00\x00\x01\x00\x00\x00"


def assoc_req(bssid: bytes, our_mac: bytes, ssid: str, trailer_ies: bytes = b"",
              privacy: bool = True) -> bytes:
    """Association Request; ``trailer_ies``: forced-PSK RSN IE (PMKID) / WPS vendor IE / none.
    ``privacy=False`` for a confirmed-open target -- some AP firmware rejects (status 12) a claim mismatching its actual capability; a lenient one let it slide (confirmed live, both ways)."""
    cap = struct.pack("<H", _CAP_ESS | (_CAP_PRIVACY if privacy else 0))
    listen = struct.pack("<H", 0x0001)
    ies = ssid_ie(ssid) + rates_ie() + ext_rates_ie() + trailer_ies
    return _hdr(b"\x00\x00", bssid, our_mac) + cap + listen + ies
