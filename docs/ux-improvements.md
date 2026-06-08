# caeruleus UX improvements — 2026-05-15

Twelve changes scoped after the first BLECTF run, where the friction was real
enough to be worth recording before another session goes by. Reading-order is
"smallest payoff per line first" — Tier 1 is shippable in an afternoon, Tier 3
reshapes how the tool feels.

The gatttool CLI-compatibility requirement is **dropped** as of this doc;
output format and flag names are free to diverge where it makes the tool
clearer.

---

## Tier 1 — small, high-leverage cleanups

### 1. `listen --trigger-value` defaults `--trigger-handle` to the listen handle

**Why.** The notify/indicate flags (F10–F13) all needed a value-handle write
*before* the firmware would push a notification. I issued the same pair four
times: `-a 0xH --trigger-handle 0xH --trigger-value 01`. The handles are
always identical.

**Approach.** In `listen`, when `--trigger-value` is set but `--trigger-handle`
is empty, fall back to the listen handle. Explicit `--trigger-handle` still
overrides for the cross-handle write case.

**Before**

```
./caeruleus listen -b $ADDR -a 0x003d -d 5 \
    --trigger-handle 0x003d --trigger-value 01
```

**After**

```
./caeruleus listen -b $ADDR -a 0x003d -d 5 --trigger-value 01
```

---

### 2. One-line `KEY=value` output for `read` and `write` by default

**Why.** Today `read` prints two lines (`Characteristic value/descriptor:
HEX\n                          ascii: STR`) — gatttool's format. Greppable
but awkward; I had to `grep ascii:` then strip whitespace. With the gatttool
compat requirement dropped, the natural shape is one line of structured
fields.

**Approach.** Default format becomes one line per result:

```
0x0029 hex=53636f72653a... ascii="Score: 0/17 [FFFFFFFFFFFFFFFFF]"
```

`write` mirrors the shape: `0x002b written=20 type=request`. `--format
gatttool` opts back into the old two-line shape for anyone with existing
parsers; `--json` unchanged.

**Before**

```
$ ./caeruleus read -b $ADDR -a 0x0029 -A | grep -oE 'Score:.*'
Score: 9/17 [TTTTTTTTTFFFFFFFF]
```

**After**

```
$ ./caeruleus read -b $ADDR -a 0x0029 | grep -oE 'BLE\{[^}]*\}|Score:.*'
Score: 9/17 [TTTTTTTTTFFFFFFFF]
```

---

### 3. `enumerate --values` default false

**Why.** `enumerate` today reads every readable characteristic to populate
the `HEX` / `ASCII` columns. On a 24-char device that's ~5 seconds of
ReadValue round-trips. Most of the time the user wants the tree shape,
not every payload.

**Approach.** Flip the default. `--values` becomes opt-in. Returns are
faster for the common discovery case.

**Before** — `./caeruleus enumerate -b $ADDR` (5 s, reads everything)

**After** — `./caeruleus enumerate -b $ADDR` (~600 ms, tree only).
Add `--values` when you want the dump:
`./caeruleus enumerate -b $ADDR --values`.

---

### 4. `disconnect` and `forget` subcommands

**Why.** When a peripheral got wedged ("Connected=true but the link is
dead" — what we hit after the bdaddr `HCIDEVRESET`), the only recovery
paths were `dbus-send` incantations or restarting bluetoothd. Recovery
should be a one-liner.

**Approach.** Two new subcommands:

- `caeruleus disconnect -b $ADDR` — `org.bluez.Device1.Disconnect()`,
  waits for `Connected=false`, exits clean.
- `caeruleus forget -b $ADDR` — `Adapter1.RemoveDevice()`, BlueZ purges
  its cached Device1 entirely. Next connect re-discovers from scratch.

**Example flow** — recover from a stuck connection without bluetoothd
restart:

```
$ ./caeruleus disconnect -b $ADDR
$ ./caeruleus forget -b $ADDR
$ ./caeruleus read -b $ADDR -a 0x0029   # fresh discovery + connect
```

---

### 5. `mtu --reset` / `--set` always drain peripherals

**Why.** `mtu` already drains active peripherals before restarting
bluetoothd — but only when there's a config change to write. Calling
`mtu --reset` when main.conf already says 517 skips the drain and
restart, which left the *previous* `mtu --set` session's peripheral
half-attached.

**Approach.** Always drain + restart when `--set` or `--reset` is
invoked, regardless of whether the file content changed. The restart is
the user-visible effect they're asking for.

**Before** — `mtu --reset` is silently a no-op if main.conf already
matches; any stale active connections persist.

**After** — `mtu --reset` is "kick everything back to defaults" reliably.

---

### 6. Bash + zsh completion

**Why.** Handles like `0x0049`, MAC addresses, and the subcommand list are
all guess-typed today. Cobra emits completion scripts for free.

**Approach.** Add a `completion` subcommand (cobra default). Document
sourcing in the README. Static for now (subcommand names, flag names);
dynamic handle/UUID completion off a live device is M+.

**Example flow**

```
$ source <(./caeruleus completion zsh)
$ ./caeruleus <TAB>
bdaddr   characteristics   completion   disconnect   enumerate
forget   listen   monitor   mtu   primary   read   scan   shell   write
```

---

## Tier 2 — workflow

### 7. `batch` mode for piped scripting

**Why.** The `shell | heredoc` pattern I kept reaching for is awkward
because `shell` uses readline. Readline writes prompts, draws spinners,
intercepts Ctrl-C oddly when stdin isn't a TTY. For scripting we want a
no-frills "read line, execute, print result, repeat."

**Approach.** New `batch` subcommand. Same command dispatch as `shell`,
but no readline, no async notification pump, no colours. Stdin → command;
stdout → result. Connects once on first command that needs the device,
disconnects on EOF.

**Before**

```bash
cat <<EOF | ./caeruleus shell -b $ADDR --timeout 30 2>&1 | grep ascii:
connect
char-read-hnd 0x0015
quit
EOF
```

**After**

```bash
echo "read 0x0015" | ./caeruleus batch -b $ADDR
```

Multi-command:

```bash
./caeruleus batch -b $ADDR <<EOF
read 0x0015
write 0x002b -s "BLE{FOO}" --req
read 0x0029
EOF
```

---

### 8. `--retry N --retry-delay D` on `read`, `write`, `listen`

**Why.** Stale state, BlueZ's auto-rediscover lag, supervision-timeout
windows — all of these manifest as transient first-attempt failures the
caller's expected to wrap in bash retry loops. Better to have it
built-in.

**Approach.** Two flags shared across `read`/`write`/`listen`:
`--retry N` (default 0, no retry) and `--retry-delay 500ms`. On any error
classified as transient (matches the same list as our Connect-retry
heuristic in `bluez.isStuckConnectError`), wait + retry. After N
attempts return the last error.

**Before**

```bash
for i in 1 2 3; do
  ./caeruleus read -b $ADDR -a 0x0029 -A && break
  sleep 1
done
```

**After**

```bash
./caeruleus read -b $ADDR -a 0x0029 --retry 3 --retry-delay 1s
```

---

### 9. Permission early-fail

**Why.** Subcommands that touch root-only kernel interfaces
(`monitor`, `bdaddr`, `mtu --set`, `mtu --reset`) silently begin work
when run unprivileged and fail *during* the operation — sometimes after
partial state changes. The MTU rollback path catches this for `mtu` but
the others didn't.

**Approach.** Each privileged subcommand calls a small `requireRoot()`
helper at entry that checks `os.Geteuid() == 0` (allowing for setcap'd
binaries by also checking `capabilities` where available). Failure is a
clean message before any side effect:

```
error: bdaddr --set requires root (try: sudo caeruleus bdaddr --set ...)
```

---

## Tier 3 — bigger lifts

### 10. Persistent connection daemon

**Why.** Each CLI invocation reconnects: ~1.5 s on this peripheral. The
17-flag run was ~30 reconnects = ~45 s of overhead — half the wall time
of the run. A daemon that holds the GATT link open and accepts commands
over a Unix socket would amortize that cost to a single connect.

**Approach.** New `serve` subcommand:

```
caeruleus serve -b $ADDR --socket /tmp/caeruleus.sock
```

Daemon owns one bluez.Conn + one connected Device. Accepts client
connections on the socket. Each client sends one command (same syntax as
`batch`), daemon executes against the live GATT link, returns the
result, client disconnects. The daemon stays up until SIGTERM.

Client subcommands check `CAERULEUS_SOCK` env var; when set, they
forward the command over the socket instead of opening their own
BlueZ connection. Opt-in via env so plain `caeruleus …` keeps working.

**Caveat:** MVP is single-client-at-a-time (serialized). Multi-client
concurrency is M+.

**Before** — 17 flag reads + 17 submits = 34 invocations × 1.5 s ≈ 51 s
of reconnect overhead.

**After**

```bash
caeruleus serve -b $ADDR --socket /tmp/g.sock &
export CAERULEUS_SOCK=/tmp/g.sock
for cmd in "read 0x0029" "write 0x002b -s 'BLE{X}' --req" ...; do
  caeruleus $cmd     # forwarded over the socket, no reconnect
done
kill %1
```

---

### 11. Native CCCD write via raw L2CAP

**Why.** F16 today is "write `0100` to the value handle and hope the
firmware interprets it as a CCCD enable" — a coincidence of this
peripheral's firmware. The general-purpose fix is to ATT-write `0001`
directly to the CCCD descriptor handle, regardless of whether BlueZ
exposes it as a GattDescriptor1 object. BlueZ hides CCCDs for
characteristics that don't advertise NOTIFY, which is exactly when you
need them.

**Approach — two layers.**

Layer A (cheap, BlueZ-mediated) — `caeruleus cccd write -b $ADDR
--char 0x004d --enable notify`. Find the corresponding GattDescriptor1
object (BlueZ exposes it when notify *is* advertised) and write the
2-byte value via D-Bus. Closes the gap for the "I want to subscribe but
forgot the right primitive" case.

Layer B (M4 territory) — when BlueZ doesn't expose the CCCD descriptor,
open a raw L2CAP socket to ATT CID `0x0004` against the peer's existing
LE connection and emit an ATT Write Request (opcode `0x12`) addressed
to the CCCD handle directly. This requires either:

- the kernel allowing a second L2CAP socket on a BlueZ-owned LE
  connection (some kernel versions allow this; behaviour is variable);
- or stopping bluetoothd and using `HCI_CHANNEL_USER` for exclusive
  controller access — full M4 fuzzing-mode work.

MVP ships Layer A + the framework for Layer B with a clear fall-through
error message indicating which scenario the user hit. The full
raw-L2CAP-coexist-with-bluetoothd path is a follow-up.

**Before** — F16 required ad-hoc value-handle bombing and hcimon capture.

**After (Layer A, for chars that advertise notify)**

```
$ ./caeruleus cccd write -b $ADDR --char 0x003d --enable notify
0x003e written value=0100
```

**After (Layer B target — for the F16 case)**

```
$ ./caeruleus cccd write -b $ADDR --handle 0x004e --value 0100 --raw
0x004e written via L2CAP ATT (raw)
```

---

### 12. `read --watch --every`

**Why.** Polling a stateful characteristic today means using `shell
loop-read 0xH N`. Discoverability is low; the iteration count is awkward
when you want "until I Ctrl-C." A first-class watch flag on `read` is
cleaner.

**Approach.** Two flags on `read`:

- `--watch` — read until SIGINT or `--duration` expires.
- `--every 250ms` — poll interval; default 100 ms.

Prints one line per read (or only when the value changes, with
`--changes-only`).

**Before**

```bash
echo -e "connect\nloop-read 0x003b 1000\nquit" | ./caeruleus shell -b $ADDR
```

**After**

```bash
./caeruleus read -b $ADDR -a 0x003b --watch --every 100ms --changes-only
```

---

## Addendum: HCIDEVRESET removed (2026-05-15)

After landing the twelve items above, we hit a stuck-INQUIRY state where
the Intel controller was no longer reporting LE advertisements (visible on
a phone via nRF Connect but not from the host). Root cause: `bdaddr --set`
calls `HCIDEVRESET` (an `ioctl` on `/dev/hci0`) to apply the vendor BD_ADDR
write, and that ioctl reliably leaves the controller in `UP RUNNING
INQUIRY` on this Intel chip. INQUIRY mode silently suppresses LE scan
results until a soft power-cycle.

**Change.** Removed `HCIDEVRESET` entirely. The "apply" step for vendor
writes is now `Adapter1.Powered=false → true` (BlueZ MGMT API), which has
the same observable effect on the BD_ADDR change without the INQUIRY
side-effect. `internal/bdaddr.ResetAdapter` is now a doc-only comment so
nothing accidentally re-introduces the path.

Compatibility:
- `--no-reset` on `bdaddr` is now a hidden alias for the renamed
  `--no-apply`. Behaviour unchanged.
- New `caeruleus adapter power on|off|cycle` and `caeruleus adapter info`
  subcommands as the manual rescue when external tools or kernel resets
  leave the controller wedged.

This satisfies "the tool should never put the controller in the stuck
state" — there's no longer any in-tree caller of HCIDEVRESET.

## AAR follow-up — failure modes observed during the UX validation run (2026-05-15)

The validation run captured 17/17 flags but hit six distinct broken states
that required manual recovery or mid-run code changes. The fixes below
target each one. Land all of P0 before any further CTF / fuzzing work;
P1/P2 are quality-of-life.

### P0 — land before next live-device run

#### F1. `mtu --reset` defaults to a median-safe value, not BLE spec max

**Why.** Today `mtu --reset` rewrites `ExchangeMTU=517` (BLE spec default).
On the test BLECTF (and many other small-MCU peripherals) MTU 517 is
unnegotiable — `Connect: Input/output error`. "Reset" should leave the
host in a working state, not the most-permissive-but-least-compatible
state.

**Approach.** Change `mtuDefault` from 517 to 247. 247 is the
de-facto-interoperable floor; ~all peripherals can negotiate it. Add an
explicit `mtu --reset --to-spec-default` for the historical 517 case.

**Before**

```
$ caeruleus mtu --reset           # writes 517, breaks small peripherals
```

**After**

```
$ caeruleus mtu --reset           # writes 247, works ~everywhere
$ caeruleus mtu --reset --to-spec-default   # writes 517 for "use whatever the peer supports"
```

---

#### F2. `mtu --set` and `mtu --reset` remember the previous value

**Why.** Today there's no way to undo an `mtu --set` short of re-typing
the previous value. If you `mtu --set 444` for one operation and then
want to go back, you must remember what was set before.

**Approach.** Before any write to `main.conf`, snapshot the previous
`ExchangeMTU` value into a sidecar file (`main.conf.caeruleus.prev`).
New `mtu --revert` subverb reads the snapshot and restores.
`mtu --reset` still goes to safe-median (F1); `--revert` is "undo the
last change."

**Before**

```
$ caeruleus mtu --set 444
$ # …operations…
$ caeruleus mtu --set 247   # had to remember 247 was the original
```

**After**

```
$ caeruleus mtu --set 444
$ # …operations…
$ caeruleus mtu --revert    # restores whatever was set before --set 444
```

---

#### F3. `bdaddr --set` default flips to vendor-write-only semantics

**Why.** Today `bdaddr --set XX` runs vendor write + `HCIDEVRESET`. The
`HCIDEVRESET` step breaks LE scan on the test Intel adapter for the
duration of the connection window — exactly when you want to use the
spoofed MAC. `--no-apply` (vendor write only) actually works. The default
should be the working path.

**Approach.** Flip the default: `bdaddr --set XX` is now vendor-write-only.
The chip starts using `XX` for outgoing LE connections immediately, LE
scan keeps working, but bluetoothd's `Adapter1.Address` stays at the
old cached value (real for outbound spoofing, just doesn't update the
"display" address). Add `--refresh-bluez` for users who specifically
need bluetoothd to display the new address (vendor write + HCIDEVRESET +
conditional INQUIRY clear, the old default).

**Before**

```
$ caeruleus bdaddr --set 11:22:...           # spoofs, but breaks LE scan
$ caeruleus read -b ADDR -a 0xH              # fails: "not seen during discovery"
$ caeruleus bdaddr --set 11:22:... --no-apply  # workaround
```

**After**

```
$ caeruleus bdaddr --set 11:22:...           # spoofs, scan keeps working
$ caeruleus read -b ADDR -a 0xH              # works
$ caeruleus bdaddr --set 11:22:... --refresh-bluez  # opt in to old behaviour
```

---

#### F4. Connect retry no longer calls `RemoveDevice` on discovery-side errors

**Why.** Today `Device.Connect`'s retry classifies "Input/output error",
"not seen during discovery", and "le-connection-abort-by-local" all as
transient and runs `RemoveDevice` before retrying. For stuck-Connected
state this is correct. For the other two, `RemoveDevice` purges the
cached Device1 we'd actually need for the next connect — making the
retry fail when the first attempt would have succeeded if we'd just
waited.

**Approach.** Split `IsTransientError` into two predicates:

- `IsStuckConnect(err)` — only matches errors that indicate BlueZ's
  state is wrong (`Operation already in progress`, certain "already
  connected" variants). Retry path: `RemoveDevice` + reconnect.
- `IsTransientLE(err)` — matches I/O errors, discovery timeouts, link
  aborts. Retry path: wait + reconnect (no `RemoveDevice`).

`Device.Connect` picks the right retry path based on which predicate
matches. Plain transient errors no longer wipe the cache.

---

### P1 — UX hygiene

#### F5. Pre-flight LE-health check on commands that need scan

**Why.** Several broken states presented as mysterious "Connect: I/O
error" or "not seen during discovery" with no hint about cause. The
proximate signal — "LE scan returns nothing for >3 s while a device is
known to be nearby" — is testable.

**Approach.** New helper `verifyLEHealthy(ctx, timeout)`: starts a
discovery, waits up to `timeout` (default 3 s) for any `InterfacesAdded`
or RSSI `PropertiesChanged` event. If nothing fires, return an error
with the hint "LE scan appears wedged — try `caeruleus adapter power
cycle`."

Called automatically:
- before `scan` when `--health-check` is set (default on)
- on the failure path of `read`/`write`/`listen` after a discovery-side
  error, to differentiate "device truly not present" vs "your radio is
  dead"

Opt-out: `--no-health-check` for scripts that already manage this.

---

#### F6. Reconcile adapter address sources

**Why.** During the run, `adapter info` reported `Adapter1.Address=2C:7B:...`
while `bdaddr --show` simultaneously reported `MGMT=11:22:...`. Both
were "right" from their data sources (bluetoothd cache vs MGMT live
read), but the disagreement was confusing and the user couldn't tell
which was authoritative.

**Approach.** `adapter info` reads both and prints both with labels.
When they disagree, surface the mismatch explicitly:

```
$ caeruleus adapter info
adapter=hci0 name=praetorian powered=true discovering=false
addr-bluez=2C:7B:A0:B0:55:D0     # bluetoothd cache (used by Adapter1.Address)
addr-mgmt=11:22:33:44:55:66      # chip-live via MGMT
WARN: BlueZ cache is stale; use `caeruleus bdaddr --refresh-bluez` to update
```

`bdaddr --show` stays MGMT-only since the chip-live answer is what
matters for spoofing decisions.

---

#### F7. `cccd write` Layer A repurposed to use `StartNotify`

**Why.** Today's Layer A returns "no CCCD visible" on every char
because BlueZ doesn't expose CCCDs as `GattDescriptor1` objects (BlueZ
manages them internally). The help suggests it works for chars that
advertise notify; in reality it works for nothing. Misleading.

**Approach.** Repurpose: `cccd write --char 0xH --enable notify` calls
BlueZ's `StartNotify` on the characteristic (which BlueZ implements as
"write 0x0100 to the CCCD" internally). `--enable off` calls
`StopNotify`. Doesn't literally write the CCCD bytes, but achieves the
same observable effect.

`--raw` (Layer B) keeps the existing "not yet implemented; M4" stub for
when raw L2CAP arrives.

**Before**

```
$ caeruleus cccd write --char 0x003d --enable notify
error: char 0x003d has no CCCD visible via BlueZ — expected for chars without notify/indicate.
```

**After**

```
$ caeruleus cccd write --char 0x003d --enable notify
0x003d StartNotify=ok (CCCD effectively 0100)
```

---

### P2 — quality of life

#### F8. Wrap common opaque errors with hint text

**Why.** `Connect: Input/output error` and `not seen during discovery`
both took the user multiple recovery attempts to diagnose. The
recovery procedure exists; the messages should point to it.

**Approach.** Wrap these errors at the cli layer with a hint, while
keeping the original wrapped via `%w` for programmatic consumers:

- `Connect: Input/output error` → `Connect: Input/output error (often:
  MTU too high or post-HCIDEVRESET; try mtu --set 247 or adapter power
  cycle)`
- `not seen during discovery` → `not seen during discovery (LE scan
  may be wedged; try adapter power cycle)`

---

#### F9. Confirmation prompt on disruptive operations

**Why.** `mtu --set` and `mtu --reset` disconnect all active
peripherals and restart bluetoothd. Big hammer. Easy to fire by
accident in a shell history-recall.

**Approach.** Add `-y/--yes` flag. Without it, when stdin is a TTY,
prompt:

```
$ caeruleus mtu --set 444
This will disconnect 1 connected peripheral and restart bluetoothd. Continue? [y/N]
```

Non-TTY stdin (scripts, batch mode) keeps current behaviour — no prompt.

---

#### F10. `caeruleus doctor`

**Why.** Diagnosing a broken state today requires running 4-5 commands
(`adapter info`, `hciconfig`, `bdaddr --show`, parsing main.conf,
checking `Adapter1.Discovering`). A one-shot health summary would
collapse that.

**Approach.** New `doctor` subcommand: prints a checklist with each
item as `OK` / `WARN` / `FAIL` plus a suggested fix:

```
$ caeruleus doctor
adapter hci0:
  Powered             OK    true
  Discovering         OK    false (no leaked discovery)
  Address agreement   WARN  BlueZ=2C:7B:... MGMT=11:22:... (stale cache)
                            fix: bdaddr --refresh-bluez
  LE scan healthy     OK    saw 3 advertisements in 3s
  ExchangeMTU         WARN  configured=517, recommend ≤247 for small peripherals
                            fix: mtu --set 247
  bluetoothd          OK    active
```

Reuses F5's LE-health probe and F6's address-reconciliation.

## CTF run 4 audit (2026-05-17)

Fourth pass at the BLECTF (after lazy-connect + auto-buffer landed). 17/17
with no manual interventions. Below is a feature-coverage matrix and the
small set of fixes that this run surfaced.

### What's exercised and works

| Surface | Status |
|---|---|
| `doctor` (text + new `--json`) | ✅ green start + finish; six checks |
| `scan` (with empty-result hint) | ✅ |
| `enumerate` (default + new `--compact` + `--values` + `--json`) | ✅ — `--compact` cuts table output by ~50% |
| `read` (default, `--extract`, `--watch --duration --changes-only`, `--retry`, `--ascii`, `--legacy`) | ✅ |
| `write` (default, `-n`/`-s`, `--each-line` with auto-buffer, `--retry`) | ✅ |
| `listen` (`--trigger-value` auto-count=1, explicit `--count`, `--extract`, `--monitor`, `--hidden`) | ✅ |
| `monitor` (`--extract` parity with listen, `--handle`, `--duration`) | ✅ |
| `mtu` (`--show`, `--set`, `--reset`, `--reset --to-spec-default`, `--revert`, `--dry-run`, `--yes`) | ✅ all branches taken |
| `bdaddr` (`--show`, `--set` default no-apply, `--vendor` forced, `--list-vendors`) | ✅ |
| `adapter` (`info` compact + `--verbose`, `power on/off/cycle`) | ✅ |
| `disconnect`, `forget` standalone | ✅ |
| `batch` with heredoc | ✅ |
| `serve` + `send` daemon mode | ✅ — **~10× faster** than direct invocation (80-110ms vs 600-1500ms per op) |
| `cccd write --enable notify/off` Layer A (StartNotify) | ✅ on a notify-advertising char |
| `cccd write --raw` (Layer B stub) | ✅ returns clear "M4 not implemented" |
| `primary`, `characteristics` (gatttool-style) | ✅ |
| `brute` (default changes-only + `all` mode) | ✅ |
| `loop-read` | ✅ |
| Cobra-auto `completion` | ✅ |
| `requireRoot` early-fail (monitor, bdaddr, mtu --set) | ✅ |
| Error wrappers (`hintWrap`) | ✅ — observed `Input/output error` wrap with MTU hint |

### What's still untested

| Surface | Why untested | How to test |
|---|---|---|
| **`shell` interactive mode** (readline) | needs a TTY; piping stdin degrades to batch-like | drive via `expect` or a pty (e.g. `script -qec './caeruleus shell -b X' /dev/null <<<'...'`). Verify history file, async notify pump above prompt, color prompt. |
| **`notify-on` / `notify-off` shell builtins** | only available inside `shell` | test inside an `expect` session — `notify-on 0x0043`, do something to trigger, see async output above prompt |
| **`bdaddr --refresh-bluez`** | risks the stuck-INQUIRY state we fixed; intentionally avoided | run on a known-throwaway adapter; verify the conditional INQUIRY-clear logic kicks in and HCIDEVRESET applies the change |
| **`--retry` on `write` and `listen`** | no transient failure encountered in this run | force failure (e.g. break ACL mid-write via a parallel `adapter power off` to provoke a retry trace) |
| **Concurrent multi-client `serve`** | MVP is single-client serial | open two `send` clients to the same socket simultaneously; verify they serialize cleanly without deadlock |
| **`read --watch` infinite (until SIGINT)** | only tested with `--duration` | run without `--duration`, send SIGINT, verify clean shutdown |
| **`--retry` exhaustion** | retries always succeeded | inject a permanent error, verify the final error preserves the original via `errors.Is` |
| **`mtu --revert` after a `mtu --reset`** | only revert-after-set was tested | reset → revert; expect the previous-value snapshot to load |

### Issues surfaced this run

1. **`write -n` consumed `--req` as its value when an upstream `$(read --extract)` returned empty.** Cascade made debugging confusing. Fixed: explicit `"--"` prefix detection on `--value` with an actionable error message pointing at the upstream-empty-return case.
2. **`brute "all" mode` reported "5 distinct response(s)" when all 5 were identical** — the counter was incrementing on every print, not every distinct value. Fixed: track distinct values separately from printed lines.
3. **MTU 444 connect flaked once mid-run** — a transient I/O error. The `hintWrap` produced a useful hint ("try mtu --set 247 or adapter power cycle"). Cleared after one `adapter power cycle`.
4. **Multi-notify decoy pattern still requires bash regex.** For chars where the firmware emits a decoy before the real flag, the caller's bash needs `grep -E '^(20)?424c45'` to skip the decoy. Deliberately not adding a tool-side filter for this — the pattern is too target-specific.

### Landed in this round

- `enumerate --compact` — one `key=value …` line per char/descriptor. 51% fewer bytes than the table on a 24-char tree. Useful for grep / pipes / LLM consumption.
- `doctor --json` — structured findings array with `check / status / value / fix` per item. Exits non-zero on FAIL for scripting.
- `write --value` empty/quoted-arg detection — explicit error pointing at the upstream-empty cause.
- `brute` counter fix — distinct count is now actually distinct.

### Recommended next moves

In rough priority:

1. **Test `bdaddr --refresh-bluez` against a fresh peripheral** — that path is the riskiest piece of code that's never been validated since the INQUIRY-recovery refactor.
2. **`shell` interactive mode test harness** — even a single `expect` script that verifies prompt → command → response → prompt would catch a whole class of regressions. The shell is the only major untested code path.
3. **Multi-client `serve` stress test** — open 2-3 concurrent `send` calls, watch for races. MVP claims serial; verify the mutex actually serialises and doesn't deadlock.
4. **`--retry` exhaustion path** — kill the BLECTF mid-run and verify the read/write/listen retries gracefully, surfaces the underlying error, exits with a non-zero status.
5. **(Document) "stdin should be fully buffered" pattern for any user-built pipeline** that hits BLE on both sides — `--each-line` now handles it automatically but the principle applies to other shell scripting around the tool.

## Shell harness landed (2026-05-17)

`cmd/shell-harness` is now in tree. It spawns `caeruleus shell` on a pty
(via `github.com/creack/pty`) and drives the readline-based interactive
flow programmatically. Without it, the shell was the only major code
path we'd been changing without any end-to-end verification — every
prior CTF run used `batch`, which bypasses readline entirely.

**Coverage (13 cases):**

- *Smoke* (no peripheral): banner, prompt, help, unknown-command error,
  `primary` no-device hint, `quit` clean exit.
- *History*: `~/.caeruleus_history` is created with content after one
  command + quit.
- *Device* (requires `--addr`): in-shell `connect`, `read` one-line
  format, `primary`, `characteristics`, `disconnect`, **plus the
  notification-pump async-output path** (`notify-on` + trigger write →
  expect `[notify 0x…]` to appear out-of-band).

**Invocation:**

```sh
make test-shell                                    # smoke + history
make test-shell-device ADDR=XX:XX:XX:XX:XX:XX     # smoke + history + device
go run ./cmd/shell-harness --help                  # raw
```

`--keep-running` continues past the first failure. Exit 0 only when
every case passes.

### Real bug surfaced by the harness

First run of the notify-pump test failed with `StartNotify: Not Connected`
even though the shell's prompt indicated a connected state. Root cause:
the harness's first close() implementation sent SIGKILL to the child,
which bypassed `caeruleus`'s deferred `session.close()` (the 2-second
wait for `Adapter1.Connected=false`). bluetoothd's view of the LE link
lagged the actual teardown; the next test's `connect` returned
"successfully" because Connected was still cached true, but the
subsequent StartNotify hit the dead socket.

Fixed in the harness by sending `quit` over the pty and waiting up to
3 s for graceful exit before falling back to Kill — gives the child's
defers time to run.

**Follow-up landed same session:** `runShell` now installs SIGTERM /
SIGHUP handlers that call `rl.Close()` + `cancel()`. Readline returns
`io.EOF`, the main loop exits via the existing clean path, all defers
run including `session.close()` (which waits up to 2s for
`Adapter1.Connected=false`). SIGINT is intentionally left for readline
to handle as Ctrl-C / line interrupt. SIGKILL we can't help with.

Verified by a new `SIGTERM converts to graceful shutdown` test in the
harness: spawns shell, connects, sends SIGTERM, asserts the child
exits status 0 (not signal-terminated). Without the handler the test
catches `WaitStatus.Signaled() == true` and reports a clear failure.

### Coverage matrix update

`shell` interactive mode and `notify-on / notify-off` move from the
"still untested" table above to validated. The remaining unvalidated
items:

- `bdaddr --refresh-bluez` — code path exists, still never exercised
- multi-client `serve` concurrency — MVP serial is verified
- `--retry` exhaustion (all attempts fail) — only happy-path retries
  observed
- `read --watch` until SIGINT — only `--duration` path covered
- Signal-driven shell exit (the bug above) — currently leaks state;
  harness papers over with graceful `quit`

## Code review findings (2026-05-17)

After landing the signal-handler, a structured pass over the codebase
turned up one real bug and a handful of smells worth normalising. The
findings below are in rough priority order.

### HIGH — `shell.startNotificationPump` data race on session state

**Symptom (latent).** The pump goroutine reads `sh.s.tree.Characteristics`
(a slice) and `sh.s.device` (a pointer) without any synchronisation,
while `cmdConnect` and `cmdDisconnect` reassign both from the readline
loop's goroutine. Go's memory model gives no guarantee for concurrent
read-write of a slice header — a torn read could deliver a stale data
pointer with a fresh length, or vice versa. Map iteration concurrent
with reassignment can fatal-panic.

We haven't seen this fire because the race window is small (the user
doesn't usually `connect` mid-notification stream), but it's a real
correctness issue. Fix:

- Introduce `sh.sessMu sync.RWMutex` on the shell struct.
- `RLock` around the ~10 `sh.s.tree` and `sh.s.device` reads.
- `Lock` around the ~4 reassignments in `cmdConnect`, `cmdDisconnect`,
  and the `notifyOff` path.

Read-heavy access pattern → RWMutex over plain Mutex.

### MEDIUM — `serve.go` `bufio.Scanner` calls don't set an explicit buffer

`batch.go` and `write.go` configure 64 KiB line buffers via
`scanner.Buffer(make([]byte, 0, 4096), 65536)`. `serve.go`'s two scanner
calls don't, leaving the default 64 KiB limit but with no documented
intent. Aligning them prevents future drift and makes the line-size
contract explicit.

### MEDIUM — `splitFields` doesn't handle backslash escapes

The shell's tokenizer supports `"`-quoted strings but no `\"` for a
literal quote inside one, and no `\\` for a literal backslash. Anyone
writing a JSON-shaped payload from inside `shell` will hit this. Fix:
extend the state machine with a `prev == '\\'` escape case that emits
the next rune literally.

### MEDIUM — `doctor.go` calls `os.Exit(2)` directly

Bypasses cobra's RunE error-return convention. Convert to a typed
error (`type exitWith struct{ code int }`) that `main.go` unwraps via
`errors.As` and forwards to `os.Exit`. Keeps the exit-code semantics
(2 for "checks failed") but the exit point stays in `main`.

### LOW — magic timeouts scattered across the tree

~10 distinct sub-second sleeps (50/200/300/400/500/800 ms) in
`disconnect.go`, `common.go session.close`, `mtu.go applyMTU`,
`adapter.go setPower`, `bluez.Connect retry`. Each is "wait briefly
for state to settle and re-check." Consolidate into

```go
func pollUntil(ctx context.Context, pred func() bool, interval, max time.Duration) error
```

Used everywhere a state transition needs confirmation. Saves ~30 lines
of repeated time-loop boilerplate.

### LOW — inconsistent error wrapping (`%v` vs `%w`)

Most error chains use `fmt.Errorf("X: %w", err)` (preserves the
unwrap chain so `errors.Is` / `errors.As` work). A handful use `%v`,
which loses the chain — most notably in some `bluez/bluez.go` and
`bdaddr/bdaddr.go` wrap sites. Sweep and normalise to `%w` unless
there's a specific reason not to.

Separately: `hintWrap` (the user-facing fix-suggestion appender) is
only applied in `Device.connectOnce`. The same hint shape would help
in `Characteristic.WriteValue` and `Descriptor.WriteValue` failure
paths. Extend hintWrap usage to those sites.

### LOW — `send` subcommand has no `MaximumNArgs`

`cobra.MinimumNArgs(1)` accepts any number of args; we silently
`strings.Join(args, " ")`. Either pin to `MaximumNArgs(1)` and require
the caller to quote, or document the join behaviour explicitly. Pinning
is the safer move — surprising joins are a worse failure mode than a
loud "too many args" error.

### LOW — `cccd.go` documentation-as-dead-code

```go
var _ = "00002902-0000-1000-8000-00805f9b34fb"
```

…is a non-idiomatic way to "preserve documentation for future Layer B
work". Convert to `const cccdUUID = "..."` and let the compiler accept
the unused const, or move the value into a regular comment.
Similarly the Layer B stub's `_ = payload` could be `_ []byte` in the
signature for clarity.

## Implementing in this session

Order matches the priority above. Each lands as its own focused edit so
a reviewer can pick them apart later.

## Out of scope but worth flagging for next pass

- Dynamic shell completion of handles/UUIDs off a live device — needs
  the daemon (#10) to be useful.
- Concurrent multi-client `serve` — needs request queuing + per-request
  GATT operation semantics. Worth doing once the single-client mode has
  miles on it.
- A real fuzzing engine on top of `cccd write --raw` — M4 in the brief.
  Mutators, corpus management, crash artifacts as `.btsnoop`.
