---
name: caeruleus
description: Use when performing hardware-agnostic BLE security testing on Linux/BlueZ - device scanning, GATT enumeration, read/write/notify interaction, fuzzing, and security assessment (unauthenticated read/write exposure, encryption enforcement, DFU entry, write-without-response abuse, connection parameters). Drives the single Go `caeruleus` binary; no separate server process, no external tool wrapping.
compatibility: Linux with BlueZ (bluetoothd) and a standard BLE adapter. Ships as a single self-contained `caeruleus` binary; some commands need root (raw HCI/L2CAP). Harness-agnostic - usable from any Agent Skills-compatible agent.
allowed-tools: Bash Read
---

# Caeruleus BLE Security Testing

**`caeruleus` is a single Go binary that talks to BLE peripherals over BlueZ D-Bus and raw L2CAP/HCI sockets.** Every subcommand takes `-b <BDADDR>` and supports `-o json`. This skill drives that binary: pick the command for the task, and for an assessment, chain the `recon` / `assess` / `conn-params` commands and correlate their JSON findings into a report.

It is hardware-agnostic and self-contained - just a BLE adapter and BlueZ. No Python, no separate server, no sniffer/relay hardware, and it never shells out to other tools. (Off-path sniffing of other devices and MITM/peripheral-clone work are out of scope - use dedicated hardware for those.)

## Setup

Use the provided `caeruleus` release binary: put it on `PATH` (e.g. `sudo install -m755 caeruleus /usr/local/bin/`) and run `caeruleus`. You need Linux with `bluetoothd` running and an adapter (default `hci0`); `caeruleus doctor` checks this.

A few commands need **root** (raw HCI/L2CAP or system config): `conn-params`, `monitor`, `fuzz write --raw`, `cccd --raw`, `raw-write`, `mtu --set/--reset`, `bdaddr --set`. Run those with `sudo caeruleus …`; for unattended use, a scoped sudoers drop-in (`"$USER ALL=(root) NOPASSWD: $(command -v caeruleus)"` in `/etc/sudoers.d/caeruleus`) avoids prompts.

> Building from source is only needed if you weren't given a binary: `make build` at the repo root produces `./caeruleus`.

## Common tasks

```bash
A=AA:BB:CC:DD:EE:FF                 # target (from: caeruleus scan)

caeruleus scan                       # discover devices (names, addr type, RSSI)
caeruleus enumerate -b $A --values   # full GATT tree + read each value
caeruleus read  -b $A -a 0x0013      # read a handle (or -u <uuid>)
caeruleus write -b $A -a 0x0015 -s "hello"      # write a string (-n for hex)
caeruleus listen -b $A -a 0x001e --duration 10s # capture notifications

# subscribe, write a command, and capture the notification response (single command)
# do NOT use separate write + listen — the notification fires within ms and you'll miss it
caeruleus listen -b $A -a 0x0012 --trigger-value 01
# use --trigger-handle if the write and notify characteristics differ; see listen --help for all flags

caeruleus recon -b $A                # device profile + GATT audit (fingerprint)
caeruleus assess check-auth -b $A    # what an unpaired attacker can read
caeruleus pair -b $A                 # pair/bond; caeruleus unpair -b $A to drop it
caeruleus assess dfu -b $A           # detect a DFU service + unauthenticated entry

caeruleus shell -b $A                # interactive REPL against one device
caeruleus doctor                     # adapter / bluetoothd health check
```

Add `-o json` to any command to get machine-readable output for scripting or reporting. **When you use `-o json` or `-o jsonl`, treat that output as authoritative. Do NOT re-run the same command in text mode "for display" — the JSON contains all the same data and re-running wastes tokens and time. Parse the JSON directly.**

## Command reference

### Discovery
| Command | Purpose |
|---|---|
| `scan [-t secs]` | LE discovery; `--new` hides cached devices. |
| `enumerate -b A [--values] [--compact]` | Full GATT tree; `--values` reads each characteristic; `--compact` is one line/char. |
| `primary -b A` / `characteristics -b A` | gatttool-style service / characteristic listing. |

### GATT operations
| Command | Purpose |
|---|---|
| `read -b A (-a 0xHND \| -u UUID) [--watch --every D] [--extract]` | Read; `--extract` emits bare hex for piping. |
| `write -b A (-a 0xHND\|-u UUID) (-n HEX \| -s STR) [--req] [--each-line]` | Write; `--req` forces write-with-response. |
| `raw-write -b A -a 0xHND (-n HEX \| --length N --pattern HH)` | Single-PDU ATT Write Request over raw L2CAP (oversized, bypasses BlueZ fragmentation; root). |
| `listen -b A -a 0xHND [--trigger-value HEX] [--duration D]` | Subscribe to notifications/indications. |
| `cccd -b A (--char UUID\|--handle 0xHND) --enable notify\|indicate\|off [--raw]` | Manipulate the CCCD directly. |
| `mtu -b A --show` | Show negotiated ATT MTU (`--set N` reconfigures bluetoothd; root). |

### Connection management
| Command | Purpose |
|---|---|
| `pair -b A` / `unpair -b A` | Establish / drop a bond (pairing rejection is recorded, not an error). |
| `conn-params -b A` | Connection interval / peripheral latency / supervision timeout + ATT MTU (root). |
| `disconnect -b A` / `forget -b A` | Drop the link / purge BlueZ cache (clears stuck `Connected=true`). |

### Scripting & automation
| Command | Purpose |
|---|---|
| `shell -b A` / `batch -b A` / `serve`+`send` | Interactive REPL / stdin script / persistent warm-link daemon. |

### Security assessment (structured findings)
All emit `{address, test, summary, findings[]}`; findings carry `severity` (info/low/medium/high/critical), `handle`, `uuid`, `evidence`, `detail`. **They exit 0 even when issues are found** - findings are data.

| Command | What it tests |
|---|---|
| `recon -b A` | Fingerprint + audit: DFU presence, exposed serial, custom services, hidden-readable characteristics. |
| `assess check-auth -b A [--probe-write]` | What an unpaired attacker can read; values are scanned with Titus and a secret match escalates to high. `--probe-write` also tests unauthenticated writes (same-value write-back). |
| `assess encryption -b A` | Unauthenticated baseline, pair, re-test: no-pairing exposure, enforcement, legacy fallback after unpair. |
| `assess dfu -b A [--probe-entry]` | Detect 0xFE59 DFU + unauthenticated buttonless entry. `--probe-entry` is **destructive** (reboots target). |
| `assess wwr -b A [--sizes ...] [--burst N]` | Write-without-response overflow sweep + rapid-fire burst with a liveness probe (can crash a fragile target). |

`check-auth` and `recon` use the Praetorian [Titus](https://github.com/praetorian-inc/titus) rule set to flag values that are structured secrets (API keys, tokens, private keys). Plain credential-looking text (e.g. `user:pass`) is reported as readable-without-auth but not auto-escalated.

### Fuzzing
| Command | Purpose |
|---|---|
| `fuzz write -b A -a 0xHND [--type req\|cmd\|both] [--max-iter N] [--max-time D]` | Fuzz writes with an on-disk corpus and crash/hang triage. Output dir `fuzz-out-<ts>/`. |
| `fuzz write … --raw [--include prep,exec]` | Drive raw L2CAP (oversized single-PDU + multi-part writes); root. |
| `fuzz write … --target-reset "CMD"` | Run a recovery shell command when the target locks up. |
| `fuzz replay DIR/file` | Re-send a saved corpus/crash input to reproduce. |

### Adapter & diagnostics
| Command | Purpose |
|---|---|
| `doctor` | One-shot health check (bluetoothd, power, scan, MTU, address); exit 2 on FAIL. |
| `adapter power on\|off\|cycle` / `adapter info` | Soft adapter recovery / state. |
| `bdaddr --show` / `--set MAC` | Read / spoof adapter BD_ADDR (root; vendor-specific). |
| `monitor -b A [--handle 0xHND]` | Passive HCI decode of notifications BlueZ hides (root). |

## Global flags

`-b/--bdaddr` target, `-i/--adapter hciN` (default `hci0`), `--addr-type public|random` (force if a connect fails), `-t/--timeout N` seconds, `-o/--format text|json|jsonl`, `-v/--verbose`, `-q/--quiet`.

## Assessment methodology

Run in order, capturing each step's JSON, then synthesize. Each command's `-o json` output is the single source of truth — read and parse it directly. Never re-run a command without `-o json` to see a "human-readable version"; the data is identical and the BLE round-trip is wasted. If a step locks up the device, run `disconnect` / `forget` or `adapter power cycle` before continuing.

```bash
A=AA:BB:CC:DD:EE:FF

caeruleus doctor -o json                                   # 0. adapter sane?
caeruleus recon             -b $A -o json > recon.json      # 1. profile + audit
caeruleus assess check-auth -b $A -o json > checkauth.json  # 2. unauth read exposure
caeruleus assess encryption -b $A -o json > enc.json        # 3. encryption enforcement
caeruleus assess dfu        -b $A -o json > dfu.json        # 4. DFU exposure (detect-only)
sudo caeruleus conn-params  -b $A -o json > conn.json       # 5. timing profile
caeruleus assess wwr        -b $A -o json > wwr.json         # 6. optional, can crash
# 7. optional deep dive: fuzz a writable characteristic found above
caeruleus fuzz write -b $A -a 0xHND --max-time 2m
```

Then **correlate**: merge all `findings[]`, dedupe by `(uuid, title)`, rank by severity, and chain related findings into attack narratives (e.g. *a secret read by check-auth* + *no encryption enforced* = unauthenticated secret disclosure). Use `recon`'s `profile` (manufacturer/model/firmware/serial) for chipset/CVE context. Produce a Markdown report grouped by severity, with each finding's `evidence`, and remediation per type (enforce pairing/encryption, tighten permissions, authenticate DFU, validate write lengths).

## Findings JSON schema

```jsonc
{
  "address": "AA:BB:CC:DD:EE:FF",
  "test": "check-auth",
  "summary": "readable-unauth=16 auth-required=0 ...",
  "findings": [
    {
      "title": "Secret readable without authentication",
      "severity": "high",                 // info|low|medium|high|critical
      "handle": 21,                        // ATT handle (decimal in JSON)
      "uuid": "00ca0002-bede-ad43-4145-52554c455500",
      "evidence": "...hex... (\"...ascii...\")",
      "detail": "Titus matched rule \"...\"; value read over an unpaired link."
    }
  ]
}
```

`recon` is the exception: it emits `{address, profile{...}, findings[]}`.

## Operational notes

- **`-o json` / `-o jsonl` output is authoritative and complete.** Do not re-run a command in text mode after running it with `-o json`. The JSON contains every field the text table shows (and more). Parse it directly — re-running doubles the BLE traffic for zero additional data.
- **Random vs public addresses:** if a connect fails, pass `--addr-type random` (or `public`). `scan` shows each device's type.
- **Stuck state:** "Operation already in progress" / `Connected=true` that won't clear -> `caeruleus forget -b A` then retry, or `caeruleus adapter power cycle`. `doctor` suggests the fix.
- **Single-connection peripherals:** many small devices accept one central at a time. The tool disconnects on exit; for many sequential operations use `serve` + `send` to hold one warm link.
- **Pairing rejection is a result,** not a failure: `pair` / `assess encryption` exit 0 and record it.
- **`assess wwr` and `assess dfu --probe-entry` are active/destructive** - only run against targets you can recover (they may reset the device).
