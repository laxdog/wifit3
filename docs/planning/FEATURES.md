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

**Stage 2b — DONE.** Clone the real portal instead of showing a generic template:

- `campaigns/eviltwin/client_bridge.py` (`ClientBridge`): the client-role mirror of `IpBridge`
  (associate to the *real* target, bridge its Data frames to a TAP). `dot11/eth.py:to_dot11` was
  fixed along the way — ToDS addr3 must carry the real DA per spec, not always the BSSID; the old
  hardcoding silently dropped every broadcast DHCP exchange (confirmed on real hardware).
- `net/dhcp_client.py`: a one-shot DHCP client. Doesn't use a bound UDP socket for send *or*
  receive — confirmed live that a broadcast DHCP reply is never kernel-delivered to a
  `SO_BINDTODEVICE` socket on an addressless interface, and a normal send from one picks the
  default route's source IP instead of `0.0.0.0`. Sends are hand-built frames injected directly;
  receives come off a queue of decoded Ethernet frames `ClientBridge` feeds it.
- `net/portal_http_client.py` + `net/dns_client.py`: fetches whatever the target serves on port
  80, following same-port redirects. A redirect can land on a hostname (common for cloud-hosted
  portals) rather than a bare IP — `dns_client.py` resolves that against the target's own DHCP-
  supplied DNS server, since the OS resolver isn't scoped to the fetch TAP. If the gateway itself
  doesn't answer, a second attempt probes `captive.apple.com/hotspot-detect.html` (what a real
  device does to find a portal that only intercepts traffic, not its own IP); an un-intercepted
  literal Apple "Success" response means there's no portal to clone.
- `campaigns/eviltwin/portal_fetch.py` (`fetch_real_portal`): orchestrates all of the above,
  always best-effort — any failure at any stage just falls back to the generic template, never
  blocks the twin from starting. Wired into `EvilTwinCampaign` behind
  `EvilTwinInput.clone_real_portal` (dual-card only: no spare radio for it single-card).
- `campaign.portal_fetch_error` / `campaign.cloned_real_portal` / `campaign.fetching_real_portal`
  surface progress/outcome to the UI status line.

**Verified end-to-end on real hardware** (two AR9271s, one as the "real target" running an open
twin of its own, the other running the fetch): full DISCOVER→OFFER→REQUEST→ACK round trip with no
retransmission after the ACK; the ARP+TCP-connect mechanism the HTTP fetch depends on was proven
separately over an isolated addressed TAP (the two-role test collides both roles onto the same
`10.13.37.0/24` subnet in one netns — a same-host test artifact, not reproducible against a real,
physically separate target).

**Known limitation, not attempted:** a cloned page whose login form submits over HTTPS can't be
intercepted — this app runs a plain HTTP portal server, and terminating TLS for an arbitrary
hostname would need generating a matching cert and getting the client to trust it (full MITM,
a much bigger and riskier build). `portal_fetch.py` already refuses to chase an HTTPS redirect
when *fetching* the real portal for the same reason, so this is a symmetric, deliberate boundary
rather than a one-sided gap. A cloned page's *non-form* assets (CSS/JS/images on other domains)
still load normally through the shared internet connection when NAT is up, so styling is usually
intact even though the two are unrelated mechanisms.

**force_open (done, beyond the original Stage 2b scope):** `EvilTwinInput.force_open` twins a
*secured* target open anyway (no 4-way, no capture) instead of requiring the target to already be
open — the classic "no password" lure against a network the operator already controls or is
authorized to test. Required fixing `dot11/ap.py:beacon_clone`, which had no way to strip the RSN
IE / clear the Privacy bit: harmless for a genuinely open target (nothing to strip) but a real bug
for a secured one forced open, since the twin's *beacon* would still claim WPA2 even though the
probe/assoc responses correctly went open.

**Captive-portal auto-dismiss (done, beyond the original Stage 2b scope):** `net/http_portal.py`
now tracks which client IPs have already POSTed the form and answers each OS's own background
connectivity-check path (Apple `hotspot-detect.html`/`success.html`, Android `generate_204`,
Windows `connecttest.txt`/`ncsi.txt`, Firefox `success.txt`) with the literal "you have real
internet" response once a client is authorized — otherwise the OS's own probe never stops seeing
a redirect and its sign-in sheet never dismisses itself, even after the user submits the form.

More portal templates: `VOUCHER` (access code), `PHONE` (number capture), `ROOM` (hotel room +
surname), alongside the original `PASSWORD`/`LOGIN`/`CLICKTHROUGH`.

**Considered, not built — Karma/MANA-style probe response.** Today's `FakeAP` only answers probes
for the one specific target SSID (plus wildcard probes asking "what's nearby"). A Karma-style
responder instead answers *any* directed probe with a matching AP, so a device with an open SSID
in its saved-network list joins automatically without ever being near the real network. This is a
materially different device (per-probed-SSID state, not one target) and a genuinely new attack
mode, not a variant of the existing one — worth a class-design discussion before building, not an
extension to slot into `FakeAP` unasked.
