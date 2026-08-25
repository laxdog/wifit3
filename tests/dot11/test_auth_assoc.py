"""dot11.auth_assoc: the raw Open-System auth + Association Request frame builders."""
import struct

from wifit3.dot11.auth_assoc import assoc_req, auth_req

_BSSID = bytes.fromhex("aabbccddeeff")
_OUR_MAC = bytes.fromhex("112233445566")

_CAP_OFFSET = 24   # 24-byte mgmt header, then the 2-byte capability field


def _capability(frame: bytes) -> int:
    return struct.unpack("<H", frame[_CAP_OFFSET:_CAP_OFFSET + 2])[0]


def test_assoc_req_defaults_to_ess_plus_privacy():
    """Existing callers (WPS, PMKID) target WPA/WPA2 networks; the default must keep claiming
    Privacy so their behavior is unchanged by adding this parameter."""
    frame = assoc_req(_BSSID, _OUR_MAC, "TestNet")
    assert _capability(frame) == 0x0011


def test_assoc_req_privacy_false_clears_the_privacy_bit():
    """A confirmed-open target: claiming Privacy anyway is what a real, strict carrier AP
    rejected with status 12 (a lenient hostapd target let the same mismatch slide)."""
    frame = assoc_req(_BSSID, _OUR_MAC, "TestNet", privacy=False)
    assert _capability(frame) == 0x0001


def test_assoc_req_privacy_false_still_carries_trailer_ies():
    trailer = b"\xdd\x04\x00\x50\xf2\x04"   # a minimal vendor IE, shape doesn't matter here
    frame = assoc_req(_BSSID, _OUR_MAC, "TestNet", trailer_ies=trailer, privacy=False)
    assert frame.endswith(trailer)


def test_auth_req_is_open_system_algorithm_zero():
    frame = auth_req(_BSSID, _OUR_MAC)
    assert frame[24:26] == b"\x00\x00"   # algorithm 0 (Open System)
    assert frame[26:28] == b"\x01\x00"   # sequence 1
