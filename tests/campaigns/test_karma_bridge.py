"""KarmaBridge: the Data-frame <-> TAP glue across N radios, each its own bssid, all sharing one
TAP. Exercised without a real TAP device or socket (a fake ``tap`` stands in). The one thing
``IpBridge`` never had to do: learn which radio a client is reachable through, and route (or
flood) downlink accordingly.
"""
import asyncio
from types import SimpleNamespace

import pytest

from wifit3.campaigns.karma.bridge import KarmaBridge
from wifit3.dot11.eth import LLC_SNAP_PREFIX

_BSSID_A = bytes.fromhex("9483c48c3f78")
_BSSID_B = bytes.fromhex("aabbccddeeff")
_CLIENT_A = bytes.fromhex("02aabbccddee")
_CLIENT_B = bytes.fromhex("021122334455")
_ARP = bytes.fromhex("0806")
_BROADCAST = b"\xff" * 6


class _FakeTap:
    def __init__(self):
        self.written: list[bytes] = []

    def write(self, frame: bytes) -> None:
        self.written.append(frame)


class _FakeIface:
    def __init__(self, name: str):
        self.name = name
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


def _uplink_frame(bssid: bytes, client: bytes, to_ds=True):
    fc1 = 0x01 if to_ds else 0x02
    raw = (bytes([0x08, fc1]) + b"\x00\x00" + bssid + client + bssid + b"\x00\x00"
           + LLC_SNAP_PREFIX + _ARP + b"payload")
    return SimpleNamespace(type="data", raw=raw)


def _bridge():
    """Wires the per-radio RX callbacks the way ``start()`` would, without touching a real TAP."""
    iface_a, iface_b = _FakeIface("a"), _FakeIface("b")
    b = KarmaBridge([(iface_a, _BSSID_A), (iface_b, _BSSID_B)])
    b.tap = _FakeTap()
    b._running = True
    iface_a.rx_callbacks.append(b._make_on_rx(iface_a, _BSSID_A))
    iface_b.rx_callbacks.append(b._make_on_rx(iface_b, _BSSID_B))
    return b, iface_a, iface_b


async def _flush():
    await asyncio.sleep(0)


def test_rejects_empty_card_list():
    with pytest.raises(ValueError):
        KarmaBridge([])


def test_on_rx_bridges_uplink_to_the_shared_tap_and_learns_the_client():
    bridge, iface_a, iface_b = _bridge()
    # radio A's callback (index 0) only fires for radio A's own bssid.
    iface_a.rx_callbacks[0](_uplink_frame(_BSSID_A, _CLIENT_A))
    assert len(bridge.tap.written) == 1
    eth = bridge.tap.written[0]
    assert eth[0:6] == _BSSID_A and eth[6:12] == _CLIENT_A and eth[12:14] == _ARP
    assert bridge._client_card[_CLIENT_A] == (iface_a, _BSSID_A)


def test_each_radios_callback_ignores_the_others_bssid():
    bridge, iface_a, iface_b = _bridge()
    iface_a.rx_callbacks[0](_uplink_frame(_BSSID_B, _CLIENT_A))   # wrong bssid for radio A
    assert bridge.tap.written == []


def test_on_rx_ignores_downlink_and_non_data_frames():
    bridge, iface_a, _ = _bridge()
    iface_a.rx_callbacks[0](_uplink_frame(_BSSID_A, _CLIENT_A, to_ds=False))
    iface_a.rx_callbacks[0](SimpleNamespace(type="mgmt_0", raw=b"\x00" * 24))
    assert bridge.tap.written == []


async def test_tap_frame_to_a_learned_client_goes_out_its_own_radio_only():
    bridge, iface_a, iface_b = _bridge()
    iface_b.rx_callbacks[0](_uplink_frame(_BSSID_B, _CLIENT_B))    # learns client B -> radio B
    eth = _CLIENT_B + _BSSID_B + _ARP + b"reply"
    bridge._on_tap_frame(eth)
    await _flush()
    assert len(iface_b.sent) == 1 and iface_a.sent == []
    frame = iface_b.sent[0]
    assert frame[4:10] == _CLIENT_B and frame[10:16] == _BSSID_B


async def test_tap_frame_to_an_unlearned_or_broadcast_dst_floods_every_radio():
    bridge, iface_a, iface_b = _bridge()
    eth = _BROADCAST + _BSSID_A + _ARP + b"offer"
    bridge._on_tap_frame(eth)
    await _flush()
    assert len(iface_a.sent) == 1 and len(iface_b.sent) == 1
    assert iface_a.sent[0][10:16] == _BSSID_A          # each stamped with its OWN bssid
    assert iface_b.sent[0][10:16] == _BSSID_B


def test_tap_frame_noop_when_not_running():
    bridge, iface_a, iface_b = _bridge()
    bridge._running = False
    bridge._on_tap_frame(_CLIENT_A + _BSSID_A + _ARP + b"x")
    assert iface_a.sent == [] and iface_b.sent == []


def test_start_rolls_back_tap_and_never_registers_if_dhcp_fails():
    """Same contract as ``IpBridge``: a partial bring-up failure must not leak the TAP or leave a
    stray rx callback on ANY of the radios for the next attempt to trip over."""
    iface_a, iface_b = _FakeIface("a"), _FakeIface("b")
    bridge = KarmaBridge([(iface_a, _BSSID_A), (iface_b, _BSSID_B)])
    calls: list[str] = []
    bridge.tap = SimpleNamespace(open=lambda **kw: calls.append("tap.open"),
                                 start_reading=lambda cb: calls.append("tap.start_reading"),
                                 close=lambda: calls.append("tap.close"))
    bridge.dhcp = SimpleNamespace(start=_raise_runtime_error,
                                  stop=lambda: calls.append("dhcp.stop"))
    with pytest.raises(RuntimeError):
        bridge.start()
    assert calls == ["tap.open", "tap.start_reading", "dhcp.stop", "tap.close"]
    assert iface_a.rx_callbacks == [] and iface_b.rx_callbacks == []
    assert bridge._running is False


def _raise_runtime_error() -> None:
    raise RuntimeError("no cap_net_bind_service")
