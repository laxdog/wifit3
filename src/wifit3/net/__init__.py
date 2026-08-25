"""IP-layer primitives for campaigns that need a real data plane (currently just the EvilTwin
open-network clone): a TAP device bridging 802.11 Data frames to the OS's own IP stack, and a
minimal DHCP server. Linux only for now; Windows needs a Wintun-based ``TapDevice`` later.
"""
