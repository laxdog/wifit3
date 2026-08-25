"""IpBridge: the Data-frame <-> TAP glue, exercised without a real TAP device or socket (a
fake ``tap`` stands in; ``start()``/``stop()``, which touch the OS, are not under test here)."""
import asyncio
from types import SimpleNamespace

from wifit3.campaigns.eviltwin.bridge import IpBridge
from wifit3.dot11.eth import LLC_SNAP_PREFIX

_BSSID = bytes.fromhex("9483c48c3f78")
_CLIENT = bytes.fromhex("02aabbccddee")
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


def _uplink_frame(bssid=_BSSID, client=_CLIENT, to_ds=True):
    fc1 = 0x01 if to_ds else 0x02
    raw = (bytes([0x08, fc1]) + b"\x00\x00" + bssid + client + bssid + b"\x00\x00"
           + LLC_SNAP_PREFIX + _ARP + b"payload")
    return SimpleNamespace(type="data", raw=raw)


def _bridge() -> IpBridge:
    b = IpBridge(_FakeIface(), _BSSID)
    b.tap = _FakeTap()
    b._running = True
    return b


def test_on_rx_bridges_uplink_data_frame_to_tap():
    bridge = _bridge()
    bridge.on_rx(_uplink_frame())
    assert len(bridge.tap.written) == 1
    eth = bridge.tap.written[0]
    assert eth[0:6] == _BSSID and eth[6:12] == _CLIENT and eth[12:14] == _ARP


def test_on_rx_ignores_frames_not_addressed_to_our_bssid():
    bridge = _bridge()
    bridge.on_rx(_uplink_frame(bssid=_OTHER))
    assert bridge.tap.written == []


def test_on_rx_ignores_downlink_frames():
    bridge = _bridge()
    bridge.on_rx(_uplink_frame(to_ds=False))       # FromDS, not a client uplink
    assert bridge.tap.written == []


def test_on_rx_ignores_non_data_packets():
    bridge = _bridge()
    bridge.on_rx(SimpleNamespace(type="mgmt_0", raw=b"\x00" * 24))
    assert bridge.tap.written == []


def test_on_rx_noop_when_not_running():
    bridge = _bridge()
    bridge._running = False
    bridge.on_rx(_uplink_frame())
    assert bridge.tap.written == []


async def test_tap_frame_injects_downlink_802_11_data_frame():
    bridge = _bridge()
    eth = _CLIENT + _BSSID + _ARP + b"reply"
    bridge._on_tap_frame(eth)
    await asyncio.sleep(0)                          # let the fire-and-forget task run
    assert len(bridge.iface.sent) == 1
    f = bridge.iface.sent[0]
    assert f[0:2] == b"\x08\x02" and f[4:10] == _CLIENT and f[10:16] == _BSSID


async def test_tap_frame_broadcast_dst_becomes_802_11_broadcast():
    bridge = _bridge()
    broadcast = b"\xff" * 6
    eth = broadcast + _BSSID + _ARP + b"offer"
    bridge._on_tap_frame(eth)
    await asyncio.sleep(0)
    assert bridge.iface.sent[0][4:10] == broadcast


def test_tap_frame_noop_when_not_running():
    bridge = _bridge()
    bridge._running = False
    bridge._on_tap_frame(_CLIENT + _BSSID + _ARP + b"x")
    assert bridge.iface.sent == []


def test_start_rolls_back_tap_and_never_registers_if_dhcp_fails():
    """A partial bring-up failure (e.g. DHCP can't bind: no CAP_NET_BIND_SERVICE) must not leak
    the TAP device or leave a stray rx callback for the next attempt to trip over."""
    iface = _FakeIface()
    bridge = IpBridge(iface, _BSSID)
    calls: list[str] = []
    bridge.tap = SimpleNamespace(open=lambda **kw: calls.append("tap.open"),
                                 start_reading=lambda cb: calls.append("tap.start_reading"),
                                 close=lambda: calls.append("tap.close"))
    bridge.dhcp = SimpleNamespace(start=_raise_runtime_error,
                                  stop=lambda: calls.append("dhcp.stop"))
    try:
        bridge.start()
        raise AssertionError("expected the DHCP failure to propagate")
    except RuntimeError:
        pass
    assert calls == ["tap.open", "tap.start_reading", "dhcp.stop", "tap.close"]
    assert iface.rx_callbacks == []                     # never registered, or rolled back
    assert bridge._running is False


def _raise_runtime_error() -> None:
    raise RuntimeError("no cap_net_bind_service")
