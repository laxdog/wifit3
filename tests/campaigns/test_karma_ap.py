"""KarmaAP responder as a state machine: feed parsed client frames, assert responses + stats.
No fixed target -- SSIDs are learned live off probe requests, one shared BSSID for all of them.
"""
import asyncio

from wifit3.campaigns.karma import KarmaAP
from wifit3.dot11.mac import str_to_mac
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.probe import probe_req
from wifit3.dot11.auth_assoc import auth_req, assoc_req
from wifit3.dot11.ie import GENERIC_RSN_IE

_ASSUMED_MAC = "02:11:22:33:44:55"
_BSSID = str_to_mac(_ASSUMED_MAC)
_CLIENT = bytes.fromhex("02aabbccddee")
_OTHER = bytes.fromhex("001122334455")


class FakeIface:
    def __init__(self, channel: int = 1, assumed_mac=_ASSUMED_MAC, mac_address=None):
        self.sent: list[bytes] = []
        self.current_channel = channel
        self.assumed_mac = assumed_mac
        self.mac_address = mac_address
        self.callbacks: list = []

    async def send_no_wait(self, frame: bytes) -> bool:
        self.sent.append(frame)
        return True

    async def set_channel(self, channel: int, scan: bool = False) -> bool:
        self.current_channel = channel
        return True

    async def set_fake_mac(self, mac=None, bssid=None):
        return self.assumed_mac

    async def clear_fake_mac(self) -> None:
        pass

    def register_rx_callback(self, cb) -> None:
        self.callbacks.append(cb)

    def unregister_rx_callback(self, cb) -> None:
        self.callbacks.remove(cb)


def _parse(frame: bytes):
    return WlanFrameParser.parse_80211_frame(frame, 0)


async def _flush():
    await asyncio.sleep(0.01)


def _kap(**kwargs) -> KarmaAP:
    """A responder with its BSSID already resolved, bypassing ``start()``'s beacon task -- these
    tests only exercise ``on_rx``, same pattern as ``test_eviltwin_fake_ap.py``."""
    kap = KarmaAP(FakeIface(), 1, **kwargs)
    kap.bssid = _BSSID
    return kap


async def test_start_adopts_the_assumed_mac_as_bssid():
    kap = KarmaAP(FakeIface(), 1)
    await kap.start()
    assert kap.bssid == _BSSID
    await kap.stop()


async def test_start_falls_back_to_ifaces_own_mac_when_unspoofable():
    iface = FakeIface(assumed_mac=None, mac_address="aa:bb:cc:dd:ee:ff")
    kap = KarmaAP(iface, 1)
    await kap.start()
    assert kap.bssid == str_to_mac("aa:bb:cc:dd:ee:ff")
    await kap.stop()


async def test_named_probe_answered_and_ssid_recorded():
    kap = _kap()
    kap.on_rx(_parse(probe_req(_BSSID, _CLIENT, "HomeWifi")))
    await _flush()
    assert kap.stats.probes_seen == 1
    assert kap.stats.ssids_seen == ["HomeWifi"]
    resp = kap.iface.sent[0]
    assert resp[:2] == b"\x50\x00" and resp[4:10] == _CLIENT


async def test_wildcard_and_hidden_probes_ignored():
    kap = _kap()
    kap.on_rx(_parse(probe_req(_BSSID, _CLIENT, "")))
    await _flush()
    assert kap.stats.probes_seen == 0 and kap.iface.sent == []


async def test_multiple_distinct_ssids_accumulate_in_order():
    kap = _kap()
    for ssid in ("HomeWifi", "Airport_Free_WiFi", "HomeWifi"):
        kap.on_rx(_parse(probe_req(_BSSID, _CLIENT, ssid)))
    await _flush()
    assert kap.stats.ssids_seen == ["HomeWifi", "Airport_Free_WiFi"]
    assert kap.stats.probes_seen == 3


async def test_auth_assoc_marks_client_joined_with_no_4way():
    joined = []
    kap = _kap(on_client_joined=lambda mac, ssid: joined.append((mac, ssid)))
    kap.on_rx(_parse(auth_req(_BSSID, _CLIENT)))
    assert kap.stats.auth == 1
    kap.on_rx(_parse(assoc_req(_BSSID, _CLIENT, "HomeWifi", GENERIC_RSN_IE)))
    await _flush()
    cs = "02:aa:bb:cc:dd:ee"
    assert kap.stats.assoc == 1
    assert kap.stats.clients[cs].assoced and kap.stats.clients[cs].ssid == "HomeWifi"
    assert joined == [(cs, "HomeWifi")]
    assert any(f[:2] == b"\x10\x00" for f in kap.iface.sent)      # assoc resp went out
    assert not any(f[:2] == b"\x08\x02" for f in kap.iface.sent)  # never an EAPOL data frame


async def test_reassociation_does_not_refire_joined_callback():
    joined = []
    kap = _kap(on_client_joined=lambda mac, ssid: joined.append((mac, ssid)))
    kap.on_rx(_parse(assoc_req(_BSSID, _CLIENT, "HomeWifi", GENERIC_RSN_IE)))
    kap.on_rx(_parse(assoc_req(_BSSID, _CLIENT, "HomeWifi", GENERIC_RSN_IE)))
    await _flush()
    assert kap.stats.assoc == 2
    assert len(joined) == 1


async def test_auth_to_a_different_bssid_ignored():
    kap = _kap()
    kap.on_rx(_parse(auth_req(_OTHER, _CLIENT)))
    await _flush()
    assert kap.stats.auth == 0 and kap.stats.clients == {} and kap.iface.sent == []
