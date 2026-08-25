"""Pure-spec tests for the 802.11 Data <-> Ethernet-II bridge translation."""
from wifit3.dot11.eth import LLC_SNAP_PREFIX, to_dot11, from_dot11

_BSSID = bytes.fromhex("9483c48c3f78")
_CLIENT = bytes.fromhex("02aabbccddee")
_ARP_ETHERTYPE = bytes.fromhex("0806")


def test_to_dot11_wraps_ethernet_frame_from_ds():
    eth = _CLIENT + _BSSID + _ARP_ETHERTYPE + b"payload"   # dst=client, src=bssid, ...
    f = to_dot11(bssid=_BSSID, client=_CLIENT, eth_frame=eth)
    assert f[0:2] == b"\x08\x02"                            # Data, FromDS
    assert f[4:10] == _CLIENT and f[10:16] == _BSSID and f[16:22] == _BSSID
    assert f[24:30] == LLC_SNAP_PREFIX
    assert f[30:32] == _ARP_ETHERTYPE
    assert f[32:] == b"payload"


def test_from_dot11_unwraps_to_ds_frame():
    raw = (b"\x08\x01" + b"\x00\x00" + _BSSID + _CLIENT + _BSSID + b"\x00\x00"
           + LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"payload")
    eth = from_dot11(raw)
    assert eth is not None
    assert eth[0:6] == _BSSID and eth[6:12] == _CLIENT       # dst=addr3, src=addr2
    assert eth[12:14] == _ARP_ETHERTYPE and eth[14:] == b"payload"


def test_roundtrip():
    eth = _CLIENT + _BSSID + _ARP_ETHERTYPE + b"hello"
    dot11 = to_dot11(bssid=_BSSID, client=_CLIENT, eth_frame=eth)
    # Re-derive as if the AP were the sender seen by a ToDS-oriented decoder (not a real
    # roundtrip target, just confirms the SNAP/ethertype/payload segment matches byte-for-byte).
    assert dot11[24:] == LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"hello"


def test_from_dot11_rejects_protected_frames():
    raw = (b"\x08\x41" + b"\x00\x00" + _BSSID + _CLIENT + _BSSID + b"\x00\x00"
           + LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"payload")
    assert from_dot11(raw) is None


def test_from_dot11_accounts_for_qos_control():
    qos = b"\x00\x00"                                        # QoS Control field
    raw = (b"\x88\x01" + b"\x00\x00" + _BSSID + _CLIENT + _BSSID + b"\x00\x00" + qos
           + LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"payload")
    eth = from_dot11(raw)
    assert eth is not None and eth[12:14] == _ARP_ETHERTYPE and eth[14:] == b"payload"


def test_from_dot11_rejects_non_llc_snap_payload():
    raw = (b"\x08\x01" + b"\x00\x00" + _BSSID + _CLIENT + _BSSID + b"\x00\x00"
           + b"not-an-llc-snap-header" + b"payload")
    assert from_dot11(raw) is None


def test_from_dot11_rejects_short_frame():
    assert from_dot11(b"\x08\x01\x00\x00") is None
