"""Pure-spec tests for the Probe Response builder."""
import struct

from wifit3.dot11.probe import probe_resp

_BSSID = bytes.fromhex("112233445566")


def test_probe_resp_secured_advertises_privacy_and_rsn():
    f = probe_resp(_BSSID, "Net", 6, secured=True)
    cap = struct.unpack_from("<H", f, 34)[0]
    assert cap & 0x0010                                # Privacy bit set
    assert bytes.fromhex("30140100000fac040100000fac040100000fac020000") in f   # GENERIC_RSN_IE


def test_probe_resp_open_clears_privacy_and_drops_rsn():
    f = probe_resp(_BSSID, "Net", 6, secured=False)
    cap = struct.unpack_from("<H", f, 34)[0]
    assert not (cap & 0x0010)                          # no Privacy: an open twin can't prompt for a PSK
    assert bytes.fromhex("30140100000fac040100000fac040100000fac020000") not in f
