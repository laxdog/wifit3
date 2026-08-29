"""802.11 Probe Request + Probe Response builders (pure spec)."""
import struct
import time

from wifit3.dot11.ie import ssid_ie, rates_ie, ext_rates_ie, ds_param_ie, GENERIC_RSN_IE

# Probe-response capability: ESS + Short Slot Time, +Privacy when the twin is secured. Distinct
# from the auth/assoc ESS+Privacy 0x0011 (see dot11.auth_assoc). Do not conflate.
_CAPABILITY_INFO = 0x0401
_CAP_PRIVACY = 0x0010


def probe_req(bssid: bytes, our_mac: bytes, ssid: str) -> bytes:
    """Directed Probe Request for ``ssid``, addressed to ``bssid`` (RA/BSSID), from our
    forged STA. The AP answers only if the SSID matches (or it responds broadly)."""
    hdr = b"\x40\x00" + b"\x00\x00" + bssid + our_mac + bssid + b"\x00\x00"
    return hdr + ssid_ie(ssid) + rates_ie() + ext_rates_ie()


def probe_resp(bssid: bytes, ssid: str, channel: int, secured: bool = True) -> bytes:
    """Forged Probe Response with Addr1 zeroed for the caller to splice the client's MAC into
    before each injection. ``secured=False`` drops Privacy + the RSN IE for an open twin."""
    hdr = b"\x50\x00" + b"\x00\x00" + b"\x00" * 6 + bssid + bssid + b"\x00\x00"
    cap = _CAPABILITY_INFO | (_CAP_PRIVACY if secured else 0)
    fixed = (struct.pack("<Q", int(time.time() * 1_000_000))
             + struct.pack("<H", 100)                      # beacon interval, 100 TU
             + struct.pack("<H", cap))
    tags = ssid_ie(ssid) + rates_ie() + ds_param_ie(channel) + ext_rates_ie()
    if secured:
        tags += GENERIC_RSN_IE
    return hdr + fixed + tags
