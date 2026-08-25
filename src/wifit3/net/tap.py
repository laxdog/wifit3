"""Linux TAP device: a virtual Ethernet NIC we read/write raw frames on. Once it's assigned an
IP and brought up, the kernel's own IP stack handles ARP/routing for it like any real NIC, so a
plain ``socket``-based DHCP server (``net/dhcp.py``) bound to it needs no hand-rolled IP/UDP code.
"""
from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import struct
import subprocess
from typing import Callable, Optional

logger = logging.getLogger(__name__)

_TUNSETIFF = 0x400454CA
_IFF_TAP = 0x0002
_IFF_NO_PI = 0x1000
_READ_SIZE = 1518   # standard Ethernet MTU (1500) + 14-byte header + slack

# Two grants needed on python3: CAP_NET_ADMIN (create the TAP; ioctl(TUNSETIFF) alone, this part
# genuinely works via plain setcap) and CAP_NET_RAW + CAP_NET_BIND_SERVICE (DHCP/DNS/HTTP sockets:
# SO_BINDTODEVICE scopes them to just this interface, never the host's real ones; their ports are
# all <1024). `whence -p` (zsh) resolves the real binary path even when a command is aliased (e.g.
# Kali's default `ip --color=auto`); plain `which`/`command -v` echo the alias text on zsh and
# break `readlink`.
#
# The `ip link`/`ip addr` *configuration* calls (address/up/addr-add) are different: on at least
# some Kali kernels, CAP_NET_ADMIN via setcap is NOT honored for these RTNETLINK operations even
# though it demonstrably is for TUNSETIFF and for SO_BINDTODEVICE/bind()-to-privileged-port on the
# very same box (confirmed empirically: identical `ip` calls fail under setcap-only, succeed under
# `sudo`). So those calls go through `sudo -n` instead, which needs a one-time NOPASSWD sudoers
# rule (Kali's default account already has full passwordless sudo, so this is often already true).
SETCAP_HINT = ("TAP creation needs CAP_NET_ADMIN; DHCP/DNS/HTTP need CAP_NET_RAW and "
              "CAP_NET_BIND_SERVICE. `ip link`/`ip addr` need passwordless sudo (setcap alone "
              "isn't honored for those on this kernel). One-time fix:\n"
              "  sudo setcap cap_net_admin,cap_net_raw,cap_net_bind_service+ep "
              "$(readlink -f $(whence -p python3))\n"
              "  echo \"$(whoami) ALL=(root) NOPASSWD: $(readlink -f $(whence -p ip))\" | "
              "sudo tee /etc/sudoers.d/wifit3-ip && sudo chmod 0440 /etc/sudoers.d/wifit3-ip")


class TapPermissionError(PermissionError):
    """A TAP operation failed for lack of CAP_NET_ADMIN; ``str(this)`` already has the fix."""


class TapDevice:
    """A ``/dev/net/tun`` device in TAP mode: reads/writes raw Ethernet-II frames. Torn down by
    the kernel automatically when the fd closes (``IFF_PERSIST`` is never set)."""

    def __init__(self, name: str = "wifit3tap0"):
        self.name = name
        self._fd: Optional[int] = None

    @property
    def is_open(self) -> bool:
        return self._fd is not None

    def open(self, *, mac: bytes, ip: Optional[str] = None, prefix: int = 24) -> None:
        """Create the interface, set its MAC, bring it up, and (AP role) assign ``ip/prefix``.
        Client role passes ``ip=None``; the address comes later, from ``add_address``."""
        fd = os.open("/dev/net/tun", os.O_RDWR)
        try:
            ifr = struct.pack("16sH", self.name.encode("ascii"), _IFF_TAP | _IFF_NO_PI)
            fcntl.ioctl(fd, _TUNSETIFF, ifr)
        except PermissionError as exc:
            os.close(fd)
            raise TapPermissionError(SETCAP_HINT) from exc
        except OSError:
            os.close(fd)
            raise
        os.set_blocking(fd, False)
        self._fd = fd
        try:
            self._configure(mac=mac, ip=ip, prefix=prefix)
        except Exception:
            self.close()
            raise

    def _configure(self, *, mac: bytes, ip: Optional[str], prefix: int) -> None:
        mac_str = ":".join(f"{b:02x}" for b in mac)
        _run(self.name, "link", "set", "dev", self.name, "address", mac_str)
        if ip is not None:
            _run(self.name, "addr", "add", f"{ip}/{prefix}", "dev", self.name)
        _run(self.name, "link", "set", "dev", self.name, "up")

    def add_address(self, ip: str, prefix: int = 24) -> None:
        """Client role: assign the address DHCP just leased us. Deliberately no default route:
        the fetch only ever talks to the target's own gateway, on the connected subnet."""
        _run(self.name, "addr", "add", f"{ip}/{prefix}", "dev", self.name)

    def close(self) -> None:
        self.stop_reading()
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def write(self, frame: bytes) -> None:
        if self._fd is None:
            return
        try:
            os.write(self._fd, frame)
        except BlockingIOError:
            pass                      # kernel-side queue full; drop rather than block
        except OSError:
            logger.debug("tap %s: write failed", self.name, exc_info=True)

    def start_reading(self, on_frame: Callable[[bytes], None]) -> None:
        """``on_frame`` fires (synchronously) with each Ethernet-II frame the TAP hands us:
        kernel-generated ARP/DHCP replies, or anything else routed toward this interface."""
        if self._fd is None:
            return
        asyncio.get_running_loop().add_reader(self._fd, self._on_readable, on_frame)

    def stop_reading(self) -> None:
        if self._fd is not None:
            try:
                asyncio.get_running_loop().remove_reader(self._fd)
            except RuntimeError:
                pass                  # no running loop at teardown time; nothing to remove

    def _on_readable(self, on_frame: Callable[[bytes], None]) -> None:
        try:
            frame = os.read(self._fd, _READ_SIZE)
        except (BlockingIOError, OSError):
            return
        on_frame(frame)


def _run(tap_name: str, *args: str) -> None:
    try:
        # -n: fail fast (no interactive password prompt) if the sudoers rule isn't set up, rather
        # than hanging the app waiting on stdin it can't reach.
        subprocess.run(("sudo", "-n", "ip") + args, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError("`sudo` or `ip` (iproute2) not found; both required for the TAP "
                          "device") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        permission_signals = ("not permitted", "a password is required", "no tty present",
                              "sudo: sorry")
        if any(s in stderr.lower() for s in permission_signals):
            raise TapPermissionError(SETCAP_HINT) from exc
        raise RuntimeError(f"tap {tap_name}: `ip {' '.join(args)}` failed: {stderr}") from exc
