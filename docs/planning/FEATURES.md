# Wifit3 — Features & QoL Backlog

Known bugs live in `BUGS.md`.

---

## Low Priority

### Test & Fix macOS support

Figure out how to detect & access drivers from userland in OSX.

The viable path is a **codeless kext** (Info.plist only) per supported card.
Each plist declares the adapter's VID:PID with a high `IOProbeScore` so the kernel
binds the do-nothing kext and leaves the USB interface unclaimed for libusb. 
Unverified. No macOS hardware tested. Parked until someone wants it.

### Client fingerprinting

**Problem.** Clients show bare MACs; a device class (phone / laptop / PS5 / IoT) speeds target
selection. IoT (Ring/Nest/Roku/FireTV) is highest-value for scoping.

**Approach.** Emoji left of the BSSID, one `fingerprint.py`, no DB: ~50 hardcoded OUI prefixes
+ IE fingerprinting for ambiguous OUIs (Murata/Intel modules); returns `(emoji, class,
confidence)`, blank if low; full breakdown in the Focus detail panel.

**Complexity.** Moderate: display is the hard part, not the resolver. (Killed a full
OUI→vendor DB in the Scanner table: cells too cramped for vendor strings, and an OUI names the
Wi-Fi *module* maker, not the device: disambiguation needs IE fingerprinting anyway.)

### VAULT — loot manager ("HACKLEBOX")

**Problem.** Half of Wifite's UX is effectively the OS file manager: squinting at `captures/` full
of long BSSID-encoded filenames. The loot (handshakes, PMKIDs, cracked PSKs) deserves a real view,
not a directory listing.

**What.** One screen that owns everything we've captured/cracked: handshakes, PMKIDs, PSKs,
passwords, the occasional WPS PIN (→ its PSK), WEP keys (nobody uses WEP, but still). Per-entry:
add / remove / export / copy. Bulk: **Export all as Zip**, **Show directory** (`open captures/` /
`explorer.exe captures/`) for the folks who still want the files.

**Check button.** Re-authenticate against the live AP and confirm a stored PSK still works. The
association layer we're untangling now is exactly the primitive this needs (open-auth + assoc +
4-way with the candidate PSK). Rare to *have* a plaintext password, but when we do, verifying it is
a genuinely nice touch.

**Launch Hashcat.** Per-entry button to fire hashcat with the right mode/hashline (leans on the
per-attack mode map noted in the enterprise graveyard entry). Cracked PSKs auto-add back into the
VAULT. The loop closes itself.

**Complexity.** Moderate: mostly a new screen over the existing `persist/save` + `crack/hc22000_format` layers;
the "Check" path reuses the association primitive; hashcat launch is a subprocess + parse.

------------

## Chopping Block / Graveyard

### WPS improvements - Low priority (who even has a vulnerable WPS router?)

The WPS engine is built, offline-proven, and HW-validated (full PIN crack on AirLink). Gaps:
- **Lock-cycle matrix** — only AirLink soft-lock tested; exercise no-lock, long cooldowns, hard-lock.
- **Terminal hard-lock escape** — `lock.py` learns a measured backoff but loops forever on a
  perma-locked AP; bail after N zero-progress cycles and tell the user.
- **Focus WPS panel** (passive-by-default, behind a button).
- **PixieWPS** — designed in `campaigns/wps/README.md` (native, all 5 modes, no binary).
  Deferred on effort + one real dep call: **numpy**, wanted to keep the Realtek RTL819x/eCos
  2³¹–2³² seed sweep interactive (Ralink/MediaTek instant). The old glibc-dep worry is a
  non-issue (`random()` is ~30 reimplementable lines). Tractable, not a wall.

---

## Rogue AP Graveyard

**Problems.**
1. EvilTwin/RogueAP requires responses within microsecond for ACKs.
  - We cannot achieve this from software <-> USB (multi-millisecond latency).
  - Hard-MACs that auto-ACK *could* be considered. We don't want card-specific solutions!
2. No native AP/STA support on most cards.
  - We skipped most/all of the STA/AP modes from the wireless drivers we ported.
  - Monitor + Inject was the goal.
  - Rewriting all drivers to support STA/AP = Significant effort.

### EAP-MSCHAPv2 / PEAP via Rogue AP / Evil Twin — "active", big build

Most enterprise Wi-Fi is PEAP-MSCHAPv2, which cracks with hashcat `-m 5500` (DES half near-
instant via crack.sh): recovering the *domain* credential, far higher value than a PSK. The
marquee enterprise capability. PEAP wraps MSCHAPv2 in TLS, so it **can't be captured
passively**. Stand up a rogue AP / evil twin so the client auths to *you*. Active, TX-heavy,
AP-impersonating → behind the explicit-action gate; large build (target-ESSID beacon, RADIUS/
EAP state machine, cert handling). Our `campaigns.campaign` format could compose it cleanly.
worth a design pass, and an area to beat Wifite2 (no native enterprise).

When a second hashcat mode lands (`-m 4800`/`5500`), the save layer needs a per-attack
(mode + line-format) map instead of the hardcoded `-m 22000`.

## WPA3 downgrade upgrade: EvilTwin — DONE (base build)

**Path 2** below shipped as `campaigns/eviltwin/` (`FakeAP` + `Punter` + `EvilTwinCampaign`):
a minimal AP responder in the inject path, no hostapd shell-out, monitor+inject only — the
Rogue-AP-Graveyard µs-ACK-timing worry never actually blocked it, since this isn't a full
STA/AP association state machine racing real-time ACKs, just a beacon/probe/auth/assoc/EAPOL
responder. Path 1 (passive beacon-forging) is superseded and already gone from the tree.

Since the base build, added: **attack presets** (named knob bundles over the same
`EvilTwinInput` fields — WPA3 downgrade, PMF-safe CSA, open network clone, passive/no punt,
same-channel single-card, off-channel dual-card, target-one-client), **open-network cloning**
(`FakeAP(secured=False)` skips the 4-way, stop condition is "a client associated" instead of a
crackable M1/M2), and **single-client targeting** (`EvilTwinInput.target_client` restricts
`FakeAP`'s responder plus BTM/unicast-deauth punting to one MAC).

**Still open:** the captive-portal clone below (harvest-through-an-open-twin needs a real IP
data-plane, which is a separate build).

## Captive portal clone (open-network EvilTwin, phase 2)

**Stage 1 (bridge + TAP + DHCP) — DONE.** An open-twin client now gets a real IP, not just an
802.11 association:

- `dot11/eth.py`: Data MPDU <-> raw Ethernet-II translation (generalizes the LLC/SNAP
  encapsulation `dot11/eapol.py:data_header` already used for EAPOL to any ethertype).
- `net/tap.py`: a `/dev/net/tun` TAP device (AP role only; no client-role bridge yet, see Stage 2)
  brought up via `ip` (MAC = the twin's BSSID, a `10.13.37.0/24` gateway, link up).
- `net/dhcp.py`: a minimal DISCOVER/OFFER/REQUEST/ACK server, `SO_BINDTODEVICE`-scoped to just
  the TAP so it can never answer real DHCP traffic on the host's other interfaces. Once the TAP
  has an IP and is up, the **kernel's own IP stack does ARP/routing for it like any real NIC** —
  no hand-rolled IP/UDP/TCP needed for DHCP, or for HTTP/DNS in Stage 2 either.
- `campaigns/eviltwin/bridge.py` (`IpBridge`): wires the above into `EvilTwinCampaign` behind
  `EvilTwinInput.ip_layer` (the modal sets this whenever the target is open). Best-effort: a
  bring-up failure sets `campaign.ip_layer_error` and is logged, never raised — the twin still
  works association-only, same as before this stage.
- **Permissions**: TAP creation needs `CAP_NET_ADMIN` on python3 (works fine via plain `setcap`);
  `SO_BINDTODEVICE` needs `CAP_NET_RAW`; binding DHCP (67) / DNS (53) / HTTP (80) needs
  `CAP_NET_BIND_SERVICE` (all three ports <1024) — also via `setcap` on python3, confirmed
  working. `ip link`/`ip addr` (the actual bring-up: MAC/address/up) are different: **`setcap`
  does NOT work for these RTNETLINK calls on this Kali kernel**, confirmed empirically — the
  identical `ip` command fails "Operation not permitted" under capability-only, every time, but
  succeeds under `sudo`. `net/tap.py:_run()` shells those specific calls through `sudo -n ip ...`
  instead (fails fast, no interactive prompt, if the sudoers grant isn't there). One-time setup,
  documented in `net/tap.py:SETCAP_HINT`:
  `sudo setcap cap_net_admin,cap_net_raw,cap_net_bind_service+ep $(readlink -f $(whence -p python3))`
  plus a NOPASSWD sudoers rule scoped to `ip` (Kali's default account already has full passwordless
  sudo, so this is often already true). Use `whence -p`, not `which`/`command -v`: zsh's `which`
  echoes alias text (Kali aliases `ip` to `ip --color=auto`) instead of a path, breaking
  `readlink -f`.

**Stage 2a (wildcard DNS + HTTP + generic template) — DONE.** A joined client's captive-portal
probe now actually gets answered:

- `net/dns.py` (`DnsServer`): every A query answers with the twin's own IP; AAAA gets
  NOERROR/no-record (so a client racing A/AAAA doesn't wait out an IPv6 timeout). Same
  `SO_BINDTODEVICE` scoping as DHCP.
- `net/http_portal.py` (`HttpPortalServer`): any path but `/` 302-redirects to `/` (this alone
  triggers the captive-portal flow on iOS/Android/Windows, no per-OS detection-endpoint allowlist
  needed — none of them will see the exact "you have real internet" response they each check
  for); `GET /` serves the portal page; `POST` captures the submitted form fields.
- `net/portal_templates.py`: two generic pages, chosen per run (`EvilTwinInput.portal_template`,
  a "Portal page" dropdown in the modal for open targets) — **WiFi password** ("enter this
  network's password to continue", gives the PSK directly) and **Login** (generic hotel/airport
  email+password). Both are placeholders until Stage 2b below.
- `campaigns/eviltwin/portal.py` (`PortalStack`): bundles bridge + DHCP + DNS + HTTP as the one
  thing `EvilTwinCampaign` starts/stops behind `ip_layer`; `campaign.portal_submissions`
  collects whatever gets harvested. The Focus screen's tick loop
  (`screen.py:_poll_eviltwin_live_events`) logs the join and every submission *live* (an open
  twin may never auto-stop, so waiting for run-end to surface them would mean never), and
  persists each submission via `persist/save.py:save_portal_credentials` to
  `captures/<ssid>_<bssid>_<epoch>_portal.txt`.

**Verified end-to-end on real hardware** (one AR9271 as the twin, synthetic open beacon — no
target AP or phone needed): TAP came up with the twin's MAC/IP and state UP; a real DHCP
DISCOVER→OFFER round-trip leased `10.13.37.100`; `GET /` served the portal page; a redirect path
302'd to `/`; DNS A queries resolved to the twin's IP and AAAA came back empty; a `POST` was
captured and returned the success page; killing the process (even via SIGINT, not just a clean
stop) still fully tore down the TAP, sockets, and (once NAT existed) the iptables rules, because
`Campaign._drive()`'s `finally: await self.teardown()` runs on every exit path including
cancellation.

**Stage 2b.5 (internet sharing / NAT) — DONE.** `net/nat.py` (`NatGateway`): once the IP layer is
up, MASQUERADEs the twin's `10.13.37.0/24` subnet out through whichever interface currently owns
the default route (detected dynamically via `ip route show default`, read-only, never hardcoded
to a specific card), so a joined client gets real internet, not just DHCP/DNS/a portal page.

- Every rule (`POSTROUTING -j MASQUERADE`, two `FORWARD` accepts) is tagged with an iptables
  comment mark and narrowly scoped to the TAP subnet + interface pair; `stop()` removes exactly
  what `start()` added, nothing else. `ip_forward` is restored to whatever it was before (not
  forced to stay on) if this run is what turned it on.
- A partial failure mid-bring-up rolls back whatever had already been applied before raising, so
  a bad NAT attempt can't leave a half-configured rule set behind for the next run (or a stray one
  on the host) to trip over — same transactional pattern as `IpBridge`/`PortalStack`.
- **Deliberately never fatal**: no internet-connected uplink (or any other NAT failure) just sets
  `PortalStack.nat_error` and is logged — the DHCP/DNS/HTTP portal keeps working exactly as
  before. Internet sharing is a bonus on top of a working captive portal, not a requirement for
  one.
- **Verified live**, with an explicit non-regression check given the real risk of this class of
  change: baseline `ping 8.8.8.8` via the laptop's own `wlan0` before touching anything, confirmed
  it still worked *while the twin + NAT were up* (`iptables -t nat -L` showed exactly the three
  expected rules, correctly scoped to `10.13.37.0/24`/`wifit3tap0`/`wlan0`, nothing broader), and
  confirmed a clean process kill left the host in exactly its original state (no stray TAP, no
  stray iptables rules, `ip_forward` back to 0). Never touches the uplink's own address, routes,
  or any pre-existing firewall rule.

**Stage 2b (not started) — clone the real portal.** This is the one still-open piece from
tonight's asks. Deliberately not attempted yet: it's the biggest remaining chunk (a *client-role*
Data-frame bridge + a DHCP client, neither of which exist — today's bridge is AP-role only), and
rushing it risked either destabilizing the now-verified AP-role path or shipping an unverified
client-association flow with no time left to test it properly. Windows still has no TAP (needs a
Wintun driver install, later work); Linux only for now.

1. **Client-role bridge + a DHCP client.** Associate to the *real* open target and get an IP from
   it the same way a real device would (the `dot11/eth.py` translation is direction-agnostic, but
   the TAP/bridge wiring today is AP-role only — this needs its own bring-up path).
2. **Fetch the real portal, before arming the twin.** Do what a real device's OS does: hit the
   standard captive-portal-detection URLs, follow the redirect if one fires, save the returned
   login page and every same-origin asset it references (CSS/JS/images/fonts). No redirect means
   no real portal — the Stage 2a generic template is already the correct fallback.
3. **Serve the cloned page** instead of the generic template, rewriting the login form's submit
   target to land on us if the original pointed off-portal.

New preset once Stage 2b lands: a "Captive portal (cloned)" variant of `OPEN_CLONE`, versus
today's `OPEN_CLONE` which already gets clients an IP and a generic (not cloned) portal page.
