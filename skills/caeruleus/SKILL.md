---
name: caeruleus
description: Use when performing hardware-agnostic BLE security testing on Linux/BlueZ - device scanning, GATT enumeration, read/write/notify interaction, fuzzing, and security assessment (unauthenticated read/write exposure, encryption enforcement, DFU entry, write-without-response abuse, connection parameters). Drives the single Go `caeruleus` binary; no separate server process, no external tool wrapping.
compatibility: Linux with BlueZ (bluetoothd) and a standard BLE adapter; build with the Go toolchain (1.25+). Some commands require root (raw HCI/L2CAP sockets). Harness-agnostic - usable from any Agent Skills-compatible agent.
allowed-tools: Bash Read
---

# Caeruleus BLE Security Testing (Go)

**A single statically-linked Go binary (`caeruleus`) that talks to BLE peripherals through BlueZ D-Bus and raw L2CAP/HCI sockets. Every subcommand supports `-o json` for machine consumption.** This skill is the orchestration layer: it sequences the binary's commands into assessment workflows and correlates their JSON findings into a report.

Scope is deliberately **hardware-agnostic and self-contained**: it needs only a standard BLE adapter and BlueZ. It does not require Python, a separate server process, sniffer hardware, or an ESP32 relay, and it never shells out to other tools.

## When to Use

- Interacting with a BLE peripheral: scan, enumerate GATT, read/write characteristics, subscribe to notifications.
- Assessing a peripheral's security posture: what an unpaired attacker can read/write, whether encryption is enforced, DFU exposure, write-without-response resilience, connection parameters.
- Fuzzing a writable characteristic for crashes/hangs (with an on-disk corpus).
- Recovering a wedged adapter / stuck BlueZ connection during testing.

If the task needs off-path sniffing of *other* devices' traffic, or a MITM relay/peripheral clone, that is out of scope for this tool - use dedicated sniffer/relay hardware separately.

## Prerequisites & Build

- **Linux with BlueZ** (`bluetoothd` running) and a BLE adapter (default `hci0`).
- **Go toolchain** (1.25+) to build, or a prebuilt binary.

Build once from the repo root:

```bash
make build          # produces ./caeruleus  (and: make harness, make test-unit)
```

Invoke as `./caeruleus` from the repo root, or copy it onto `PATH`. In examples below the binary is written `caeruleus`.

### Root / privileges

Most commands run unprivileged over D-Bus. These need **root** (raw HCI/L2CAP or system config):

| Needs root | Why |
|---|---|
| `conn-params`, `monitor` | HCI monitor socket (CAP_NET_RAW + CAP_NET_ADMIN) |
| `fuzz write --raw`, `cccd --raw`, `raw-write` | raw L2CAP ATT socket (CAP_NET_RAW) |
| `mtu --set/--reset`, `bdaddr --set` | edits system config / vendor HCI commands |

Run those with `sudo caeruleus …`. For unattended runs, a scoped sudoers drop-in avoids prompts:

```bash
echo "$USER ALL=(root) NOPASSWD: $(command -v caeruleus || echo $PWD/caeruleus)" | sudo tee /etc/sudoers.d/caeruleus
sudo chmod 0440 /etc/sudoers.d/caeruleus
```

(Remove with `sudo rm /etc/sudoers.d/caeruleus`. Note this grants passwordless root to that binary path.)

## Global flags

Apply to every subcommand:

- `-b, --bdaddr XX:XX:XX:XX:XX:XX` - target peripheral (required by most commands).
- `-i, --adapter hciN` - adapter (default `hci0`).
- `--addr-type public|random` - force address type (auto if blank; some peripherals advertise as `random`).
- `-t, --timeout N` - per-operation timeout, seconds (default 25).
- `-o, --format text|json|jsonl` - **always use `json` when orchestrating**; `text` renders human tables.
- `-v, --verbose` / `-q, --quiet` - stderr diagnostics / suppress status lines.

## Command reference

### Discovery & interaction
| Command | Purpose |
|---|---|
| `scan [-t secs]` | LE discovery; `--new` hides cached devices. |
| `recon -b A` | Passive device profile (DIS fingerprint, service map, GATT audit). |
| `enumerate -b A [--values] [--compact]` | Full GATT tree; `--compact` is one line/char (LLM-friendly). |
| `primary -b A` / `characteristics -b A` | gatttool-compatible service / characteristic listing. |
| `read -b A (-a 0xHND \| -u UUID) [--watch --every D] [--extract]` | Read; `--extract` emits bare hex for piping. |
| `write -b A (-a 0xHND\|-u UUID) (-n HEX \| -s STR) [--req] [--each-line]` | Write; `--req` forces write-with-response. |
| `listen -b A -a 0xHND [--trigger-value HEX] [--duration D]` | Subscribe to notifications/indications. |
| `cccd -b A (--char UUID\|--handle 0xHND) --enable notify\|indicate\|off [--raw]` | Manipulate the CCCD directly. |
| `mtu -b A --show` | Show negotiated ATT MTU (`--set N` reconfigures bluetoothd; root). |
| `shell -b A` / `batch -b A` / `serve`+`send` | Interactive REPL / stdin script / persistent warm-link daemon. |

### Security assessment (structured findings)
All emit `{address, test, summary, findings[]}`; findings carry `severity` (info/low/medium/high/critical), `handle`, `uuid`, `evidence`, `detail`. **These exit 0 even when issues are found** - findings are data.

| Command | What it tests |
|---|---|
| `recon -b A` | Fingerprint + audit: DFU presence, exposed serial, custom services, hidden-readable characteristics. |
| `assess auth-bypass -b A [--probe-write]` | What an unpaired attacker can read; secret-looking values escalate. `--probe-write` also tests unauthenticated writes (same-value write-back). |
| `assess encryption -b A` | Unauthenticated baseline → pair → re-test: no-pairing exposure, enforcement, legacy fallback after unpair. |
| `assess dfu -b A [--probe-entry]` | Detect 0xFE59 DFU + unauthenticated buttonless entry. `--probe-entry` is **destructive** (reboots target). |
| `assess wwr -b A [--sizes ...] [--burst N]` | Write-without-response overflow sweep + rapid-fire burst with liveness probe (can crash a fragile target). |
| `pair -b A` / `unpair -b A` | Establish / drop a bond (pairing rejection is recorded, not an error). |
| `conn-params -b A` | Connection interval / peripheral latency / supervision timeout + ATT MTU (root). |

### Fuzzing
| Command | Purpose |
|---|---|
| `fuzz write -b A -a 0xHND [--type req\|cmd\|both] [--max-iter N] [--max-time D]` | Write fuzzing with an on-disk corpus and crash/hang triage. Output dir `fuzz-out-<ts>/`. |
| `fuzz write … --raw [--include prep,exec]` | Drive raw L2CAP solo (oversized single-PDU + Prepare/Execute writes); root. |
| `fuzz write … --target-reset "CMD" [--liveness-every N]` | Run a recovery shell command when the target wedges. |
| `fuzz replay DIR/file [--op req\|cmd]` | Re-send a saved corpus/crash input to reproduce. |

### Adapter & diagnostics
| Command | Purpose |
|---|---|
| `doctor` | One-shot health check (bluetoothd, power, scan, MTU, address) with fixes; exit 2 on FAIL. |
| `adapter power on\|off\|cycle` / `adapter info` | Soft adapter recovery / state. |
| `disconnect -b A` / `forget -b A` | Drop link / purge BlueZ cache (clears stuck `Connected=true`). |
| `bdaddr --show` / `--set MAC` | Read / spoof adapter BD_ADDR (root; vendor-specific). |
| `monitor -b A [--handle 0xHND]` | Passive HCI decode of notifications BlueZ hides (root). |

## Assessment methodology (recommended orchestration)

Run in order, capturing each step's JSON, then synthesize. Reuse one warm link where possible; if a step wedges the device, run `disconnect`/`forget` or `adapter power cycle` before continuing.

```bash
A=CC:B6:0E:3C:97:0B          # target

caeruleus doctor -o json                                   # 0. adapter sane?
caeruleus recon              -b $A -o json > recon.json     # 1. profile + audit
caeruleus assess auth-bypass -b $A -o json > auth.json      # 2. unauth read exposure
caeruleus assess encryption  -b $A -o json > enc.json       # 3. encryption enforcement
caeruleus assess dfu         -b $A -o json > dfu.json       # 4. DFU exposure (detect-only)
sudo caeruleus conn-params   -b $A -o json > conn.json      # 5. timing profile
# 6. (optional, can crash) write-without-response resilience:
caeruleus assess wwr         -b $A -o json > wwr.json
# 7. (optional, deep) fuzz a writable characteristic found above:
caeruleus fuzz write -b $A -a 0x0015 --max-time 2m
```

Then **correlate**: merge all `findings[]`, dedupe by `(uuid, title)`, rank by severity, and chain related findings into attack narratives (e.g. *auth-bypass read of a credentials characteristic* + *no encryption enforced* = unauthenticated credential disclosure). Use `recon`'s `profile` (manufacturer/model/firmware/serial) for chipset/CVE correlation and report context. Produce a Markdown report grouped by severity with evidence (`evidence` is a hex+ASCII preview) and remediation per finding type (enforce pairing/encryption, tighten permissions, authenticate DFU, validate write lengths).

## Findings JSON schema

```jsonc
{
  "address": "CC:B6:0E:3C:97:0B",
  "test": "auth-bypass",
  "summary": "readable-unauth=16 auth-required=0 ...",
  "findings": [
    {
      "title": "Characteristic readable without authentication",
      "severity": "high",                 // info|low|medium|high|critical
      "handle": 19,                        // ATT handle (decimal in JSON)
      "uuid": "00ca0001-bede-ad43-4145-52554c455500",
      "evidence": "61646d696e... (\"admin:password123\")",
      "detail": "Value retrieved over an unpaired, unencrypted link."
    }
  ]
}
```

`recon` is the exception: it emits `{address, profile{...}, findings[]}`.

## Operational notes

- **Random vs public addresses:** if connect fails, pass `--addr-type random` (or `public`). `scan` shows each device's type.
- **Stuck state:** "Operation already in progress" / `Connected=true` that won't clear → `caeruleus forget -b A` then retry, or `caeruleus adapter power cycle`. `caeruleus doctor` suggests the fix.
- **Single-connection peripherals:** many small devices accept one central at a time. Disconnect (the tool does this on exit) before re-running, or use `serve`/`send` to hold one warm link across many operations.
- **Pairing rejection is a result,** not a failure: `pair`/`assess encryption` exit 0 and record it.
- **`assess wwr` and `assess dfu --probe-entry` are active/destructive** - only run against targets you can recover (they may reset the device).
