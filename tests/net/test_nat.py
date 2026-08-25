"""NatGateway: iptables/sysctl sequencing, rollback, and the read-only uplink-detection parser.
``subprocess.run`` is mocked throughout: nothing here touches a real interface or firewall."""
import subprocess
from types import SimpleNamespace

import pytest

from wifit3.net.nat import NatGateway, default_route_iface

_SUBNET = "10.13.37.0/24"
_TAP = "wifit3tap0"


def _sudo_calls(mock_run):
    return [c.args[0] for c in mock_run.call_args_list]


# ----- default_route_iface (read-only parser) --------------------------------

def test_default_route_iface_parses_dev(mocker):
    mocker.patch("wifit3.net.nat.subprocess.run", return_value=SimpleNamespace(
        stdout="default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"))
    assert default_route_iface() == "wlan0"


def test_default_route_iface_no_default_route(mocker):
    mocker.patch("wifit3.net.nat.subprocess.run", return_value=SimpleNamespace(stdout=""))
    assert default_route_iface() is None


def test_default_route_iface_survives_command_failure(mocker):
    mocker.patch("wifit3.net.nat.subprocess.run", side_effect=OSError("ip not found"))
    assert default_route_iface() is None


# ----- NatGateway.start() -----------------------------------------------------

def test_start_noop_when_no_uplink(mocker):
    mocker.patch("wifit3.net.nat.default_route_iface", return_value=None)
    run = mocker.patch("wifit3.net.nat.subprocess.run")
    gw = NatGateway(_TAP, _SUBNET)
    gw.start()                                            # must not raise
    assert gw.uplink is None
    run.assert_not_called()                                # no sudo call at all


def test_start_noop_when_uplink_is_our_own_tap(mocker):
    """A same-named uplink would mean routing our own subnet through itself: refuse silently."""
    mocker.patch("wifit3.net.nat.default_route_iface", return_value=_TAP)
    run = mocker.patch("wifit3.net.nat.subprocess.run")
    gw = NatGateway(_TAP, _SUBNET)
    gw.start()
    assert gw.uplink is None
    run.assert_not_called()


def test_start_adds_masquerade_and_forward_rules(mocker):
    mocker.patch("wifit3.net.nat.default_route_iface", return_value="wlan0")
    mocker.patch("wifit3.net.nat._read_ip_forward", return_value="0")
    run = mocker.patch("wifit3.net.nat.subprocess.run", return_value=SimpleNamespace())
    gw = NatGateway(_TAP, _SUBNET)
    gw.start()

    calls = _sudo_calls(run)
    assert ("sudo", "-n", "sysctl", "-w", "net.ipv4.ip_forward=1") in calls
    assert any(c[:5] == ("sudo", "-n", "iptables", "-t", "nat") and "MASQUERADE" in c
              for c in calls)
    assert any("FORWARD" in c and "-i" in c and _TAP in c and "wlan0" in c for c in calls)
    assert gw.uplink == "wlan0"


def test_start_skips_forwarding_toggle_when_already_enabled(mocker):
    mocker.patch("wifit3.net.nat.default_route_iface", return_value="wlan0")
    mocker.patch("wifit3.net.nat._read_ip_forward", return_value="1")
    run = mocker.patch("wifit3.net.nat.subprocess.run", return_value=SimpleNamespace())
    NatGateway(_TAP, _SUBNET).start()
    assert not any("sysctl" in c for c in _sudo_calls(run))


def test_every_rule_is_comment_tagged(mocker):
    mocker.patch("wifit3.net.nat.default_route_iface", return_value="wlan0")
    mocker.patch("wifit3.net.nat._read_ip_forward", return_value="1")
    run = mocker.patch("wifit3.net.nat.subprocess.run", return_value=SimpleNamespace())
    NatGateway(_TAP, _SUBNET).start()
    iptables_calls = [c for c in _sudo_calls(run) if "iptables" in c]
    assert len(iptables_calls) == 3
    assert all("wifit3-nat" in c for c in iptables_calls)


# ----- rollback on partial failure -------------------------------------------

def test_partial_failure_rolls_back_earlier_rules_and_forwarding(mocker):
    mocker.patch("wifit3.net.nat.default_route_iface", return_value="wlan0")
    mocker.patch("wifit3.net.nat._read_ip_forward", return_value="0")
    # 1st call (sysctl) ok, 2nd (MASQUERADE add) ok, 3rd (first FORWARD add) fails.
    run = mocker.patch("wifit3.net.nat.subprocess.run", side_effect=[
        SimpleNamespace(), SimpleNamespace(),
        subprocess.CalledProcessError(1, "iptables", stderr="boom"),
        SimpleNamespace(), SimpleNamespace(),               # the two rollback -D calls
    ])
    gw = NatGateway(_TAP, _SUBNET)
    with pytest.raises(subprocess.CalledProcessError):
        gw.start()

    calls = _sudo_calls(run)
    # rollback ran: the MASQUERADE rule removed (-D) and forwarding restored to 0.
    assert any("iptables" in c and "-D" in c and "MASQUERADE" in c for c in calls)
    assert ("sudo", "-n", "sysctl", "-w", "net.ipv4.ip_forward=0") in calls


# ----- stop() ------------------------------------------------------------------

def test_stop_removes_exactly_what_start_added(mocker):
    mocker.patch("wifit3.net.nat.default_route_iface", return_value="wlan0")
    mocker.patch("wifit3.net.nat._read_ip_forward", return_value="0")
    run = mocker.patch("wifit3.net.nat.subprocess.run", return_value=SimpleNamespace())
    gw = NatGateway(_TAP, _SUBNET)
    gw.start()
    run.reset_mock()

    gw.stop()
    calls = _sudo_calls(run)
    assert sum(1 for c in calls if "iptables" in c and "-D" in c) == 3
    assert ("sudo", "-n", "sysctl", "-w", "net.ipv4.ip_forward=0") in calls
    assert gw.uplink is None


def test_stop_is_a_noop_when_never_started(mocker):
    run = mocker.patch("wifit3.net.nat.subprocess.run")
    NatGateway(_TAP, _SUBNET).stop()
    run.assert_not_called()


def test_stop_survives_a_failed_undo_step(mocker):
    """One failed -D must not stop the rest of the rollback from running."""
    mocker.patch("wifit3.net.nat.default_route_iface", return_value="wlan0")
    mocker.patch("wifit3.net.nat._read_ip_forward", return_value="0")
    run = mocker.patch("wifit3.net.nat.subprocess.run", side_effect=[
        SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), SimpleNamespace(),  # start()
        subprocess.CalledProcessError(1, "iptables"),         # first -D fails
        SimpleNamespace(), SimpleNamespace(), SimpleNamespace(),  # the rest still run
    ])
    gw = NatGateway(_TAP, _SUBNET)
    gw.start()
    gw.stop()                                                 # must not raise
    assert sum(1 for c in _sudo_calls(run) if "-D" in c) == 3   # all three attempted
