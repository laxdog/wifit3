"""Pure-spec tests for the 802.11 Data <-> Ethernet-II bridge translation (both directions:
AP role bridging its clients, and client role associated to a real AP)."""
from wifit3.dot11.eth import LLC_SNAP_PREFIX, to_dot11, from_dot11

_BSSID = bytes.fromhex("9483c48c3f78")
_CLIENT = bytes.fromhex("02aabbccddee")
_ARP_ETHERTYPE = bytes.fromhex("0806")


def test_to_dot11_ap_role_wraps_ethernet_frame_from_ds():
    eth = _CLIENT + _BSSID + _ARP_ETHERTYPE + b"payload"   # dst=client, src=bssid, ...
    f = to_dot11(bssid=_BSSID, station=_CLIENT, eth_frame=eth)
    assert f[0:2] == b"\x08\x02"                            # Data, FromDS
    assert f[4:10] == _CLIENT and f[10:16] == _BSSID and f[16:22] == _BSSID
    assert f[24:30] == LLC_SNAP_PREFIX
    assert f[30:32] == _ARP_ETHERTYPE
    assert f[32:] == b"payload"


def test_to_dot11_client_role_wraps_ethernet_frame_to_ds():
    eth = _BSSID + _CLIENT + _ARP_ETHERTYPE + b"payload"   # dst=bssid (gateway), src=us
    f = to_dot11(to_ds=True, bssid=_BSSID, station=_CLIENT, eth_frame=eth)
    assert f[0:2] == b"\x08\x01"                            # Data, ToDS
    assert f[4:10] == _BSSID and f[10:16] == _CLIENT and f[16:22] == _BSSID
    assert f[30:32] == _ARP_ETHERTYPE and f[32:] == b"payload"


def test_to_dot11_client_role_addr3_carries_the_real_destination_not_bssid():
    """addr3 must be the Ethernet frame's actual DA (IEEE 802.11-2020 Table 9-26), not the AP's
    BSSID: a broadcast DHCP DISCOVER must stay addressed as broadcast, or the AP-side bridge
    reconstructs it as unicast-to-itself instead of broadcast and a real DHCP server won't treat
    it as one (confirmed on real hardware: this exact bug silently dropped every DHCP exchange)."""
    broadcast = b"\xff\xff\xff\xff\xff\xff"
    eth = broadcast + _CLIENT + b"\x08\x00" + b"dhcp-discover-payload"
    f = to_dot11(to_ds=True, bssid=_BSSID, station=_CLIENT, eth_frame=eth)
    assert f[10:16] == _CLIENT                              # addr2 = SA = us
    assert f[16:22] == broadcast                             # addr3 = DA = the real destination


def test_from_dot11_unwraps_to_ds_frame_sta_to_ap():
    raw = (b"\x08\x01" + b"\x00\x00" + _BSSID + _CLIENT + _BSSID + b"\x00\x00"
           + LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"payload")
    eth = from_dot11(raw)
    assert eth is not None
    assert eth[0:6] == _BSSID and eth[6:12] == _CLIENT       # dst=addr3, src=addr2
    assert eth[12:14] == _ARP_ETHERTYPE and eth[14:] == b"payload"


def test_from_dot11_unwraps_from_ds_frame_ap_to_sta():
    raw = (b"\x08\x02" + b"\x00\x00" + _CLIENT + _BSSID + _BSSID + b"\x00\x00"
           + LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"reply")
    eth = from_dot11(raw)
    assert eth is not None
    assert eth[0:6] == _CLIENT and eth[6:12] == _BSSID        # dst=addr1, src=addr3
    assert eth[12:14] == _ARP_ETHERTYPE and eth[14:] == b"reply"


def test_roundtrip_ap_role():
    eth = _CLIENT + _BSSID + _ARP_ETHERTYPE + b"hello"
    dot11 = to_dot11(bssid=_BSSID, station=_CLIENT, eth_frame=eth)
    assert dot11[24:] == LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"hello"


def test_roundtrip_client_role():
    eth = _BSSID + _CLIENT + _ARP_ETHERTYPE + b"hello"
    dot11 = to_dot11(to_ds=True, bssid=_BSSID, station=_CLIENT, eth_frame=eth)
    back = from_dot11(dot11)
    assert back == eth


def test_from_dot11_rejects_protected_frames():
    raw = (b"\x08\x41" + b"\x00\x00" + _BSSID + _CLIENT + _BSSID + b"\x00\x00"
           + LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"payload")
    assert from_dot11(raw) is None


def test_from_dot11_rejects_ibss_and_wds_addressing():
    ibss = (b"\x08\x00" + b"\x00\x00" + _BSSID + _CLIENT + _BSSID + b"\x00\x00"
           + LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"x")
    assert from_dot11(ibss) is None
    wds = (b"\x08\x03" + b"\x00\x00" + _BSSID + _CLIENT + _BSSID + b"\x00\x00"
          + LLC_SNAP_PREFIX + _ARP_ETHERTYPE + b"x")
    assert from_dot11(wds) is None


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
