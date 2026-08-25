"""ClientBridge: the client-role Data-frame <-> TAP glue (the mirror of IpBridge), exercised
without a real TAP device (a fake ``tap`` stands in)."""
import asyncio
from types import SimpleNamespace

from wifit3.campaigns.eviltwin.client_bridge import ClientBridge
from wifit3.dot11.eth import LLC_SNAP_PREFIX

_BSSID = bytes.fromhex("9483c48c3f78")
_OUR_MAC = bytes.fromhex("02aabbccddee")
_OTHER = bytes.fromhex("001122334455")
_ARP = bytes.fromhex("0806")


class _FakeTap:
    def __init__(self):
        self.written: list[bytes] = []

    def write(self, frame: bytes) -> None:
        self.written.append(frame)


class _FakeIface:
    def __init__(self):
        self.sent: list[bytes] = []
        self.rx_callbacks: list = []

    async def send_no_wait(self, frame: bytes) -> bool:
        self.sent.append(frame)
        return True

    def register_rx_callback(self, cb) -> None:
        self.rx_callbacks.append(cb)

    def unregister_rx_callback(self, cb) -> None:
        if cb in self.rx_callbacks:
            self.rx_callbacks.remove(cb)


def _downlink_frame(bssid=_BSSID, addr1=_OUR_MAC, from_ds=True):
    fc1 = 0x02 if from_ds else 0x01
    raw = (bytes([0x08, fc1]) + b"\x00\x00" + addr1 + bssid + bssid + b"\x00\x00"
           + LLC_SNAP_PREFIX + _ARP + b"payload")
    return SimpleNamespace(type="data", raw=raw)


def _bridge() -> ClientBridge:
    b = ClientBridge(_FakeIface(), _BSSID, _OUR_MAC)
    b.tap = _FakeTap()
    b._running = True
    return b


def test_on_rx_bridges_downlink_data_frame_to_tap():
    bridge = _bridge()
    bridge.on_rx(_downlink_frame())
    assert len(bridge.tap.written) == 1
    eth = bridge.tap.written[0]
    assert eth[0:6] == _OUR_MAC and eth[6:12] == _BSSID and eth[12:14] == _ARP


def test_on_rx_ignores_frames_not_addressed_to_us():
    bridge = _bridge()
    bridge.on_rx(_downlink_frame(addr1=_OTHER))
    assert bridge.tap.written == []


def test_on_rx_accepts_broadcast_frames_like_a_dhcp_reply():
    """DHCP OFFER/ACK go to broadcast (we have no IP for the server to unicast to yet): a real
    client accepts those too, not just frames addressed to its own MAC."""
    bridge = _bridge()
    broadcast = b"\xff\xff\xff\xff\xff\xff"
    bridge.on_rx(_downlink_frame(addr1=broadcast))
    assert len(bridge.tap.written) == 1
    assert bridge.tap.written[0][0:6] == broadcast


def test_on_rx_ignores_uplink_frames():
    bridge = _bridge()
    bridge.on_rx(_downlink_frame(from_ds=False))          # ToDS, not an AP->us downlink
    assert bridge.tap.written == []


def test_on_rx_ignores_non_data_packets():
    bridge = _bridge()
    bridge.on_rx(SimpleNamespace(type="mgmt_0", raw=b"\x00" * 24))
    assert bridge.tap.written == []


def test_on_rx_feeds_on_eth_frame_hook_when_set():
    bridge = _bridge()
    seen: list[bytes] = []
    bridge.on_eth_frame = seen.append
    bridge.on_rx(_downlink_frame())
    assert len(seen) == 1 and seen[0] == bridge.tap.written[0]


def test_on_rx_noop_when_not_running():
    bridge = _bridge()
    bridge._running = False
    bridge.on_rx(_downlink_frame())
    assert bridge.tap.written == []


async def test_tap_frame_injects_uplink_802_11_data_frame():
    bridge = _bridge()
    eth = _BSSID + _OUR_MAC + _ARP + b"request"
    bridge._on_tap_frame(eth)
    await asyncio.sleep(0)
    assert len(bridge.iface.sent) == 1
    f = bridge.iface.sent[0]
    assert f[0:2] == b"\x08\x01" and f[4:10] == _BSSID and f[10:16] == _OUR_MAC


def test_tap_frame_noop_when_not_running():
    bridge = _bridge()
    bridge._running = False
    bridge._on_tap_frame(_BSSID + _OUR_MAC + _ARP + b"x")
    assert bridge.iface.sent == []


def test_start_and_stop_register_and_unregister_rx_callback():
    iface = _FakeIface()
    bridge = ClientBridge(iface, _BSSID, _OUR_MAC)
    bridge.tap = SimpleNamespace(open=lambda **kw: None, start_reading=lambda cb: None,
                                 close=lambda: None)
    bridge.start()
    assert bridge.on_rx in iface.rx_callbacks
    bridge.stop()
    assert bridge.on_rx not in iface.rx_callbacks
