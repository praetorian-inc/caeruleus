# caeruleus fuzzing - plan

> **Status (2026-06-01):** Phase 1a (write_req, write_cmd via BlueZ) and
> Phase 1b (prep, exec via raw L2CAP) both landed. Phase 2 and Phase 3
> remain future work (see end of doc).

## Goals

Add a fuzzing subsystem to caeruleus focused on **GATT application-layer
crashes** (peripheral app-logic bugs) and **ATT framing-layer crashes**
(peripheral stack bugs reachable by malformed PDUs).

Explicitly out of scope: link-layer / LL frame fuzzing. That requires an
external radio (nRF52840 + SweynTooth firmware) and is a different tool.
caeruleus stays "rides alongside BlueZ over D-Bus + raw L2CAP" - see the
README's positioning.

Pentest-use target: a pentester points caeruleus at a single peripheral
characteristic, walks away for an hour, comes back to a `crashes/` dir
containing reproducible PoC inputs that wedged the target. Not academic
novelty - predictable, reproducible, customer-shippable artifacts.

## Phasing

| Phase | Subcommand | Layer        | Transport            | PR    |
|-------|------------|--------------|----------------------|-------|
| 1a    | `fuzz write` | GATT app values | BlueZ D-Bus, or raw L2CAP with `--raw` | first |
| 1b    | `fuzz write --include prep,exec` | ATT Prepare/Execute sequences | raw L2CAP only | second |
| 2     | `fuzz att`   | ATT PDU framing (all opcodes) | raw L2CAP | future |

Phase 1a and 1b are separate commits - 1a ships standalone and is
immediately useful; 1b extends with multi-PDU sequences that need the raw
L2CAP path. Phase 2 is a follow-up after we've seen the Phase 1 design
hold up in real use.

## Architecture

```
internal/fuzz/
  mutate/     vendored go-fuzz mutators (Apache 2.0, attribution preserved)
              + small ATT-aware adapters for length-aware mutation
  corpus/     AFL-style on-disk layout: corpus/ queue/ crashes/ hangs/
              one file per input, filename = sha1(input)[:16]
  oracle/     state classifier:
                - AFLNet-style tuple hash of (req_opcode, resp_opcode,
                  err_code, response_length_class)
                - liveness probe (known-good read) between iterations
                - disconnect detector (D-Bus Connected property + L2CAP
                  socket error)
  trace/      per-iteration JSONL writer + replay loader
  engine/     main loop: pick → mutate → send → observe → classify →
              record. Pluggable harness interface so engine drives D-Bus
              (Phase 1a) or raw L2CAP (Phase 1b/2).

cli/
  fuzz.go        parent command
  fuzz_write.go  Phase 1a + 1b
  fuzz_replay.go takes a saved corpus file, sends it once, prints result
```

### Harness interface

```go
// Harness is the per-transport adapter. Phase 1a wraps BlueZ
// Characteristic.WriteValue + ReadValue; Phase 1b wraps internal/l2cap
// (Write Req/Cmd/Signed/Prepare/Execute). Phase 2 reuses the L2CAP
// harness with a wider opcode surface.
type Harness interface {
    Connect(ctx context.Context) error
    Write(ctx context.Context, op WriteOp, value []byte) (Response, error)
    LivenessProbe(ctx context.Context) error
    Reset(ctx context.Context) error   // shell command per --target-reset
    Close() error
}

type WriteOp uint8
const (
    OpWriteReq      WriteOp = iota  // 0x12 - has response
    OpWriteCmd                      // 0x52 - no response
    OpSignedWrite                   // 0xD2 - needs CSRK; v1.1+
    OpPrepareWrite                  // 0x16 - multi-PDU prefix
    OpExecuteWrite                  // 0x18 - multi-PDU finalizer
)
```

### Oracle: pseudo-coverage on a blackbox target

We can't instrument the peripheral, so we approximate coverage with
**response-tuple state hashing** (AFLNet pattern):

```
tuple = (req_opcode, resp_opcode, err_code, len_class)
```

`len_class` is a bucket - `0, 1, 2-4, 5-16, 17-64, 65-251`. Bucketing
lets us treat "20 bytes back" and "23 bytes back" as the same state
without blowing up the state set.

State set is in-memory; new tuples → admit input to `queue/` and treat
as parent for future mutations. The actual "crashes/" gate is stricter:
disconnect, liveness loss, or controller error.

### Liveness probe

Read of a known-good handle, default = lowest-numbered readable char in
the target's tree (auto-discovered at startup; falls back to handle
0x0003 if discovery fails). Override with `--liveness-handle`.

Probe is run:
- Every N iterations (default 10)
- After every iteration that returned a disconnect or socket timeout
- After every reset-hook invocation

Liveness counter increments on failure; resets on success. When counter
≥ `--target-reset-after` (default 3), the reset hook fires.

### Reset hook

Shell-only. `--target-reset "ssh root@plug ./toggle.sh && sleep 8"` - caeruleus calls `sh -c <cmd>`, waits for it to return, then re-runs
discovery + reconnect. Pentester wraps their own curl / GPIO / serial
toggle.

If no `--target-reset` is set, three consecutive liveness failures →
abort the run with a `hangs/` entry naming the last successful input.

### Seed corpus

Default: read the target's current value at startup (via BlueZ
`Characteristic.ReadValue`) and seed the corpus with it. This is the
"natural" payload the device understands - the fastest path to
interesting mutations.

Override: `--seed-file FILE` (raw bytes) or `--seed-dir DIR` (load all
files in the dir as seeds). Both can coexist with the auto-read seed.

Empty fallback: zero-byte seed.

### Trace format

`fuzz-out-<ISO8601>/run.json` - run metadata:

```json
{
  "seed": 1717207200,
  "target": "AA:BB:CC:DD:EE:FF",
  "char": "0x002a",
  "ops": ["write_req", "write_cmd"],
  "started_at": "2026-06-01T18:20:00Z",
  "ended_at":   "2026-06-01T19:20:00Z",
  "iterations": 8421,
  "crashes": 2,
  "queue_size": 31
}
```

`trace.jsonl` - one line per iteration:

```json
{"i":421,"mut":"havoc","seed_id":"a1b2c3","input":"01020304","op":"write_req","resp_op":"0x13","len":0,"live":true,"ms":42}
{"i":422,"mut":"bitflip1","seed_id":"a1b2c3","input":"01020305","op":"write_req","resp_op":"0x01","err":"0x0d","live":true,"ms":38,"new_state":true}
```

`corpus/` `queue/` `crashes/` `hangs/` - flat dirs of raw input bytes,
filename `<sha1[:16]>.bin`. Crashes get a sidecar `.json` with the
iteration metadata for quick triage.

### CLI

```
caeruleus fuzz write --char 0xHND [flags]

flags:
  --seed-file FILE        raw seed override
  --seed-dir DIR          multiple seed files
  --max-iter N            iteration cap (default 10000)
  --max-time DUR          wall-clock cap (default unlimited)
  --target-reset CMD      shell command on hang
  --target-reset-after N  trigger after N liveness failures (default 3)
  --liveness-handle HND   override auto-detected liveness handle
  --liveness-every N      probe every N iterations (default 10)
  --corpus-dir DIR        output dir (default ./fuzz-out-<ISO>/)
  --rng-seed N            deterministic mode (default time-based)
  --type req|cmd|both     write variant for Phase 1a (default req)
  --include prep,exec     enable additional opcodes (Phase 1b)
  --raw                   force raw L2CAP path (Phase 1b implies)
  --no-state-feedback     disable AFLNet-style queue admission

caeruleus fuzz replay PATH
  PATH = file or dir of crash inputs. Re-send each, print response.
```

### Reproducibility

Every run prints `seed=N` at startup and writes it to `run.json`.
Re-running with `--rng-seed N --seed-file X` produces the same sequence
of mutations (modulo target timing). Replay path takes a single input
file and just sends it.

## Vendoring policy

`internal/fuzz/mutate/` will contain a copy of dvyukov/go-fuzz's
`mutator.go` (Apache 2.0). License header preserved, file header
prepended naming the upstream version + commit SHA + license URL. Small
adaptations (rename package, drop go-fuzz-internal helpers) noted in a
`PROVENANCE.md` in the same dir. See [[feedback-vendor-over-reinvent]]
for the rationale.

## Open questions (revisit after Phase 1a ships)

- Is the auto-discovered liveness handle reliable enough, or do we need
  to fall back to a 1-byte read of the GATT primary service handle?
- How aggressive should `havoc` be (multi-mutation chains per
  iteration)? go-fuzz defaults to 16; consider lowering for slower BLE
  iteration to keep individual inputs cheap to triage.
- For Phase 1b: do we run Prepare/Execute as a single "input" (one
  corpus file = N PDUs concatenated with a length prefix), or as a
  parameterized scenario type? Current plan is the latter - easier to
  mutate piecewise.

## Prior art borrowed from

- **Quarkslab ble-gatt-fuzzing**: per-opcode field generators, seeded
  handles from real GATT tree, per-testcase trace+pcap layout.
- **protocol-fuzzing/ble-fuzzer**: alphabet-config decoupling,
  pre/step/post harness interface, per-target reset hook.
- **AFLNet**: response-tuple-hash as blackbox coverage proxy.
- **dvyukov/go-fuzz**: vendored mutator.go.
