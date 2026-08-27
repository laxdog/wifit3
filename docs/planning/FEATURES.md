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

### VAULT — loot manager ("HACKLEBOX") — DONE (core view; Check/Hashcat/add deferred)

**Problem.** Half of Wifite's UX is effectively the OS file manager: squinting at `captures/` full
of long BSSID-encoded filenames. The loot (handshakes, PMKIDs, cracked PSKs) deserves a real view,
not a directory listing.

**Shipped.** `ui/screens/vault.py:VaultView`, opened from the Scanner (hotkey `v`) -- read-only
otherwise, no radio/interface dependency, works with no card plugged in. One `DataTable` over
`persist.capture_history.load_capture_index()` (already existed, built for the Scanner's own
capture-badge history -- VAULT is genuinely "just a new screen over" it, per the original
complexity note), newest-first, re-scanned from disk on every visit (`on_screen_resume`) so a
save from a running campaign shows up next time you open it. `PersistedCapture` gained an `ssid`
field (parsed from the filename, previously discarded) so the table can show a name, not just a
BSSID. Per-entry: **Remove** (`r`, deletes the file + reloads), **Copy** (`c`, the WEP/WPS
credential itself, or -- since HS/PMKID have no single "value" -- the file's own hashcat hashline
content, via Textual's native OSC-52 clipboard). Bulk: **Export all as Zip** (`z`, always written
*beside* `captures/`, never inside it, so a re-export can never bundle a previous export into
itself) and **Show directory** (`o`, `xdg-open`/`open`/`explorer` per platform). Verified with a
real Textual SVG render (title bar, columns, newest-first ordering, footer keybindings all
correct), not just unit assertions.

**Deferred, not attempted:**
- **"add" (manually enter a credential you already have from elsewhere).** No design decided yet
  for the entry form; low value next to the read/remove/copy path that's actually built.
- **Check button** (re-authenticate against the live AP to confirm a stored PSK still works).
  Needs a real target AP in range to test meaningfully, and VAULT has no "current target"/card
  context to decide which interface would even attempt it -- a class-design question for a
  session with hardware in the loop, not a solo overnight guess.
- **Launch Hashcat** (subprocess launch of an external tool). Spawning and babysitting an external
  process has real UX questions (detached terminal? inline output? which mode per capture type?)
  worth a quick design pass rather than silently picking conventions unasked.

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

## WPA3 downgrade upgrade: EvilTwin

The Focus **WPA Downgrade** button reads as dead because the implemented path is weak. Both
paths win the same prize: the client's **EAPOL M1+M2** for a *WPA2* assoc (M2's MIC is all an
offline PSK crack needs), and both work **only on WPA3-transition** APs; Transition-Disable
kills them.

- **Path 1: passive (implemented, weak).** Forge WPA2-only beacons/probe-resps so a client
  downgrades and 4-ways with the *real* AP, sniffed passively. But the real AP still advertises
  SAE on-channel, so a sane client picks SAE → nothing to capture. (Never confirmed to inject on
  HW.) `campaigns/wpa3_downgrade.py`.
- **Path 2: evil twin (the reliable build).** Rogue AP (same SSID/BSSID, ideally a different
  channel), WPA2-only; accept auth+assoc, **send M1 yourself** (random ANonce), capture M2.
  Deterministic. A minimal AP responder in the inject path (beacon/probe/auth/assoc/M1), *not*
  a hostapd shell-out (Linux-only, breaks cross-platform). Feature-scale.

**Near-term QoL:** disable/annotate the button unless the target is WPA3-transition, and log
"passive: waiting for a natural reconnect (minutes–hours)" so it stops looking broken.
