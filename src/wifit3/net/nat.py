"""NatGateway: shares real internet (whichever interface currently owns the default route) with
clients on the twin's TAP subnet, so a joined client gets more than DHCP/DNS/a portal page.

Never touches the uplink interface's own address, routes, or existing firewall rules: only adds
narrowly-scoped MASQUERADE/FORWARD rules matched on the TAP subnet + interface pair, each tagged
with a comment mark so ``stop()`` removes exactly (only) what ``start()`` added. A failure partway
through rolls back whatever had already been applied, so a bad run never leaves a half-configured
NAT rule behind for the next attempt (or a stray one on the host) to trip over.
"""
from __future__ import annotations

import logging
import subprocess
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)

_MARK = "wifit3-nat"
_SUDO_TIMEOUT = 5


def default_route_iface() -> Optional[str]:
    """The interface currently carrying the default route, or None (no internet to share).
    Read-only (``ip route show`` needs no privilege) and never touched/modified."""
    try:
        result = subprocess.run(("ip", "route", "show", "default"),
                                capture_output=True, text=True, timeout=_SUDO_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return None


def _read_ip_forward() -> str:
    try:
        return open("/proc/sys/net/ipv4/ip_forward").read().strip()
    except OSError:
        return "0"


def _sudo(*args: str) -> None:
    subprocess.run(("sudo", "-n") + args, check=True, capture_output=True, text=True,
                   timeout=_SUDO_TIMEOUT)


def _sudo_best_effort(*args: str) -> None:
    """Teardown-only: never let a single failed undo step abort the rest of the rollback."""
    try:
        _sudo(*args)
    except Exception:                                             # noqa: BLE001
        logger.debug("nat teardown step failed (continuing): %s", " ".join(args), exc_info=True)


class NatGateway:
    def __init__(self, tap_name: str, subnet: str):
        self.tap_name = tap_name
        self.subnet = subnet                  # e.g. "10.13.37.0/24"
        self.uplink: Optional[str] = None
        self._forward_was: Optional[str] = None
        self._undo: List[Callable[[], None]] = []

    def start(self) -> None:
        """Raises on failure, after rolling back anything already applied -- except when there's
        no internet-connected interface to share (``uplink`` stays None), which is normal."""
        uplink = default_route_iface()
        if uplink is None or uplink == self.tap_name:
            logger.info("nat: no internet-connected uplink found; running without one")
            return
        self.uplink = uplink
        try:
            self._forward_was = _read_ip_forward()
            if self._forward_was != "1":
                _sudo("sysctl", "-w", "net.ipv4.ip_forward=1")
                self._undo.append(lambda: _sudo_best_effort(
                    "sysctl", "-w", f"net.ipv4.ip_forward={self._forward_was}"))
            self._add_rule("-t", "nat", "-A", "POSTROUTING", "-s", self.subnet,
                           "-o", uplink, "-j", "MASQUERADE")
            self._add_rule("-A", "FORWARD", "-i", self.tap_name, "-o", uplink, "-j", "ACCEPT")
            self._add_rule("-A", "FORWARD", "-i", uplink, "-o", self.tap_name,
                           "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
        except Exception:
            self.stop()
            raise

    def _add_rule(self, *args: str) -> None:
        """``args`` with -A; queues the matching -D (same args, tagged) for rollback/stop only
        once the rule is confirmed added, so a failed add never queues an undo for nothing."""
        marked = args + ("-m", "comment", "--comment", _MARK)
        _sudo("iptables", *marked)
        undo_args = tuple("-D" if a == "-A" else a for a in marked)
        self._undo.append(lambda a=undo_args: _sudo_best_effort("iptables", *a))

    def stop(self) -> None:
        for undo in reversed(self._undo):
            undo()
        self._undo.clear()
        self.uplink = None
