<img width="1200" height="628" alt="Caeruleus - Bluetooth Low Energy security testing, consolidated into one Go binary" src="https://github.com/user-attachments/assets/bd67cbb9-64db-4fa6-9f63-5ea5f3a1610b" />

# Caeruleus: BLE Testing Toolkit

> One Go binary for the entire Bluetooth Low Energy assessment workflow on Linux/BlueZ: scan, enumerate, read/write/notify, fuzz, and structured security assessment, with JSON output for scripts and agents.

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/github/license/praetorian-inc/caeruleus)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/praetorian-inc/caeruleus)](https://goreportcard.com/report/github.com/praetorian-inc/caeruleus)
[![Release](https://img.shields.io/github/v/release/praetorian-inc/caeruleus?sort=semver)](https://github.com/praetorian-inc/caeruleus/releases)

**Caeruleus** consolidates Bluetooth Low Energy (BLE) security testing into a single Go binary built on the Linux BlueZ stack. It talks to peripherals over BlueZ D-Bus and raw L2CAP/HCI sockets and covers the whole lifecycle: discover devices, browse and read/write the GATT tree, capture notifications, fuzz writable characteristics, and run repeatable security-assessment workflows. Every command emits structured `-o json` / `-o jsonl` output for scripting, reporting, and LLM agents. 

Built by offensive security engineers to replace the usual pile of `bettercap`, `gatttool`, `hcitool`, `bluetoothctl`, and one-off Bleak scripts, Caeruleus keeps the abstractions at the level a human or agent actually works at.

*caeruleus*: Latin for the "blue" in Bluetooth Low Energy

## Table of Contents

- [Why Caeruleus?](#why-caeruleus)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Agents Welcome](#agents-welcome)
- [Assessment Workflows](#assessment-workflows)
- [Extending Caeruleus](#extending-caeruleus)
- [Limitations](#limitations)
- [Part of the Praetorian Toolkit](#part-of-the-praetorian-toolkit)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Why Caeruleus?

The standard workflow for BLE security testing is a scavenger hunt across tools that were never designed to work together:

- **`hcitool` / `hciconfig`** for adapter config and discovery, both deprecated by BlueZ and missing from many modern distros.
- **`bettercap`** for `ble.recon` and `ble.enum`. Powerful, but you install a full network-attack framework just to browse a GATT tree.
- **`gatttool`** for reading and writing handles, deprecated for years but still in every tutorial.
- **Custom Bleak / pygatt scripts** for anything deeper.

Each speaks its own dialect, and none emit machine-readable output you can pipe into the next step, so you become the integration layer, copying MAC addresses and handles between terminals by hand. BlueZ's own supported frontends (`bluetoothctl`, `btmgmt`) are general-purpose management tools pitched at the wrong abstraction level for assessment work.

Caeruleus replaces that entire pile with one consistent command surface:

| Use case | Previous method | With Caeruleus |
|---|---|---|
| Discover nearby devices | `hcitool lescan` / `bettercap ble.recon` / `bluetoothctl scan on` | `caeruleus scan` |
| List and read services/characteristics | `bettercap ble.enum <mac>` | `caeruleus enumerate -b <mac> --values` |
| Interactive session | `gatttool -I` / `bluetoothctl` | `caeruleus shell -b <mac>` |
| Read a handle | `gatttool --char-read-hnd 0x0013` | `caeruleus read -b <mac> -a 0x0013` |
| Write a handle | `gatttool -b <mac> --char-write-req -a 0x002c -n $(...)` | `caeruleus write -b <mac> -a 0x002c --req -s "value"` |
| Capture notifications | custom Bleak logger | `caeruleus listen -b <mac> -a <handle>` |
| Audit unauthenticated exposure | custom Bleak audit scripts | `caeruleus recon` / `caeruleus assess ...` |
| Fuzz a characteristic | custom fuzzers / boofuzz | `caeruleus fuzz write -b <mac> -a <handle>` |
| Connection params, MTU | `hcitool con` / `btmgmt con-info` | `caeruleus conn-params -b <mac>` |
| Adapter power and recovery | `btmgmt power` / `hciconfig reset` / `rfkill` | `caeruleus doctor` / `caeruleus adapter power cycle` |

## Features

**Structured output everywhere.** Every command that produces output supports `-o text|json|jsonl`. JSON is the canonical representation, not a secondary export; `jsonl` streams one record per event for `scan --live` and `listen`. `enumerate --compact` emits one `key=value` line per characteristic for grep or an LLM context window.

**BLE stack health.** `caeruleus doctor` walks the BlueZ and kernel state and prints an OK/WARN/FAIL checklist: bluetoothd running, adapter powered, no leaked discovery session, BlueZ-cached address vs the MGMT chip-live address, a live 2-second scan probe, and ExchangeMTU in a safe band. Each non-OK finding carries a concrete fix command, and the exit code follows the grep/diff convention (0 clear, 2 on failure).

**Clean teardown.** On `SIGTERM`/`SIGHUP` the tool runs the disconnect path and polls until `Connected=false` propagates through BlueZ, so the peripheral re-advertises immediately instead of stalling for its supervision timeout. No more "ghost connections" after a crash.

**Scripting and automation.** `serve`/`send` hold one GATT link open over a Unix socket so a script or agent avoids the ~1.5s reconnect cost per command; `batch` runs commands from stdin over a single persistent connection; `listen --trigger-value` sets up a notification, fires a write, and captures the response atomically.

**Convenience details.** Device-type inference from GAP Appearance plus advertised services (a watch shows as "Smartwatch," not a raw appearance code); forgiving input parsing (handles as `0x002a`, `0X2A`, or `42`; hex as `deadbeef`, `de:ad:be:ef`, or `0xdeadbeef`); `caeruleus recipes` lists and keyword-searches 19 common workflows; `conn-params` surfaces the negotiated interval, latency, and supervision timeout that neither gatttool nor bettercap expose.

## Agents Welcome

Caeruleus treats LLM agents as first-class users. `-o json` / `-o jsonl` give token-efficient, structured output an agent parses without scraping human-formatted tables, and the repo ships a portable [Agent Skill](https://agentskills.io) (`skills/caeruleus/SKILL.md`) that teaches any Agent Skills-compatible assistant the command surface and a recommended assessment methodology. Point an agent at a device and it runs the whole methodology end to end.

In our benchmark, Opus 4.8 (xHigh) with Caeruleus and its skill completed the task in **62% of the time and 70% of the tokens** of the same model with free tool choice (which reached for `hcitool` and Bleak scripts).

## Installation

Caeruleus targets **Linux with BlueZ** (`bluetoothd`) and a standard BLE adapter. It does not build or run on macOS or Windows. A handful of raw-socket commands need root.

**With the Go toolchain:**

```bash
go install github.com/praetorian-inc/caeruleus/cmd/caeruleus@latest
```

**Prebuilt release binary** (x86_64 and arm64): download the archive for your architecture from the [Releases](https://github.com/praetorian-inc/caeruleus/releases) page, extract, and put `caeruleus` on your `$PATH`.

**From source:**

```bash
git clone https://github.com/praetorian-inc/caeruleus
cd caeruleus
make build        # -> ./caeruleus
make test         # unit tests + shell tests
```

## Quick Start

Sanity-check the adapter, then discover what's nearby:

```console
$ caeruleus doctor
adapter: hci0
  [  OK] bluetoothd             active
  [  OK] Powered                true
  [  OK] Discovering            false
  [  OK] Address agreement      00:1A:7D:DA:71:13
  [  OK] LE scan healthy        saw advertisements
  [  OK] ExchangeMTU            247

$ caeruleus scan
ADDRESS            TYPE    RSSI  DEVICE  NAME
------------------------------------------------------------
9C:9C:1F:F2:88:86  public  -32           BLECTF_JohnsonSpace
C4:C0:B0:3B:5B:EF  random  -59           Aranet4 06D4B
DC:FD:B4:CA:B4:E9  random  -62           JBL Boombox 2
```

Browse the full GATT tree and read every characteristic in one shot, then poke individual handles:

```console
$ caeruleus enumerate -b 9C:9C:1F:F2:88:86 --values
SVC HND  CHR HND  CHR UUID  PROPS   HEX               ASCII
0x0014   0x0015   0x2A00    R       424c457b46...     BLE{F4K3_1D3NT1TY}
0x0028   0x002d   0xFF03    R       424c457b50...     BLE{T0K3N_S4V3R}
0x0028   0x002f   0xFF05    R,W     577269746...      Write anything here

$ caeruleus read -b 9C:9C:1F:F2:88:86 -a 0x002d
0x002d hex=424c457b503447335f5455524e33527d ascii="BLE{T0K3N_S4V3R}"

$ caeruleus write -b 9C:9C:1F:F2:88:86 -a 0x002f -s "praetorian"
0x002f written=10 type=request
```

An interactive `shell` (gatttool-style verbs), a stdin `batch` mode, and a `serve`/`send` warm-link daemon are there when you need to hold one connection across many operations.

## Command Reference

| Group | Commands |
|---|---|
| Discovery | `scan`, `enumerate`, `primary`, `characteristics` |
| GATT operations | `read`, `write`, `raw-write`, `listen`, `cccd`, `mtu` |
| Connection management | `pair`/`unpair`, `conn-params`, `disconnect`, `forget` |
| Scripting and automation | `shell`, `batch`, `serve`/`send` |
| Security assessment | `recon`, `assess check-auth`, `assess encryption`, `assess pairing`, `assess wwr`, `assess dfu` |
| Fuzzing | `fuzz write` (incl. `--raw`), `fuzz replay` |
| Adapter and diagnostics | `doctor`, `adapter`, `bdaddr`, `monitor` |

Global flags on every command: `-b/--bdaddr`, `-i/--adapter` (default `hci0`), `-t/--timeout`, `-o/--format`, `-q/--quiet`, `-v/--verbose`. Privileged commands (`conn-params`, `monitor`, `fuzz write --raw`, `cccd --raw`, `raw-write`, `mtu --set`, `bdaddr --set`) need root.

New to the tool, or coming from bettercap / gatttool / bluetoothctl / nRF Connect / Bleak? Run `caeruleus recipes` for use-case-first examples. For the full per-command reference, assessment methodology, and hardware/adapter notes, see the [**Wiki**](https://github.com/praetorian-inc/caeruleus/wiki) and [`skills/caeruleus/SKILL.md`](skills/caeruleus/SKILL.md).

## Assessment Workflows

Reading and writing handles is the easy part. Caeruleus turns the ad-hoc "let me check a few things" phase into repeatable, structured assessment. `recon` fingerprints the device and audits its GATT tree; each `assess` subcommand probes one class of weakness:

- **`assess check-auth`** — what an unpaired attacker can read (or, with `--probe-write`, write)
- **`assess encryption`** — whether pairing/encryption requirements are actually enforced
- **`assess pairing`** — the SMP pairing feature exchange and downgrade resistance
- **`assess wwr`** — write-without-response overflow and rapid-fire resilience
- **`assess dfu`** — exposed, unauthenticated firmware-update entry points

Every assessment emits the same shape, `{address, test, summary, findings[]}`, with per-finding `severity`, `handle`, `uuid`, and `evidence`. Secret-looking values are cross-checked against Praetorian's [Titus](https://github.com/praetorian-inc/titus) rule set: a hardcoded key read over an unpaired link is escalated to a high-severity finding on its own.

```console
$ caeruleus assess check-auth -b CC:B6:0E:3C:97:0B -o json | jq '.findings[] | select(.severity=="high")'
{
  "title": "Secret readable without authentication",
  "severity": "high",
  "handle": 19,
  "uuid": "00ca0001-bede-ad43-4145-52554c455500",
  "evidence": "6177735f...774a61 (\"aws_access_key_id=AKIA... aws_secret_access_key=wJa\") +37 bytes",
  "detail": "Titus matched rule \"AWS API Credentials\"; value read over an unpaired, unencrypted link."
}
```

When you find a writable characteristic worth stress-testing, `fuzz write` mutates inputs against it with an on-disk corpus and automatic crash/hang triage; `fuzz replay` reproduces any crash you find:

```console
$ sudo caeruleus fuzz write -b CC:B6:0E:3C:97:0B -a 0x0015 --raw --max-iter 20 --max-time 15s
[+] target=0x0015 liveness=0x0002 seeds=13 out=fuzz-out-20260701T144803Z
[+] done iter=2 states=2 queue=2 crashes=1 hangs=0 elapsed=1m2s
```

## Extending Caeruleus

The `assess` subcommand is built on shared primitives: BLE session management, the findings schema, secret detection, and structured output. Each assessment is a self-contained Go file following the same pattern. When your team keeps repeating a manual check, adding it as a new `assess` workflow means one Go file and one line in `assess.go`; everyone gets it in the next build, with structured output and agent-drivability included. Contributions of new workflows are especially welcome.

## Limitations

Caeruleus is opinionated: it makes the most common facets of BLE interaction fast, scriptable, and agent-friendly, and deliberately leaves some things out. It operates only as the **central** in the BLE model, not as a peripheral, and it does not sniff BLE traffic, perform active Attacker-in-the-Middle (AITM/MITM), or clone peripherals.

## Part of the Praetorian Toolkit

Caeruleus integrates Praetorian's [Titus](https://github.com/praetorian-inc/titus) for secrets detection and joins a growing family of open-source offensive tools from Praetorian, including [Nerva](https://github.com/praetorian-inc/nerva) (service fingerprinting), [Vespasian](https://github.com/praetorian-inc/vespasian) (API discovery), [Hadrian](https://github.com/praetorian-inc/hadrian) (API authorization testing), and [Brutus](https://github.com/praetorian-inc/brutus) (credential testing). Same philosophy, a single binary with structured output and no dependency hell, brought down to the RF layer.

## FAQ

**What is Caeruleus?**
A free, open-source BLE security testing tool from Praetorian: a single Go binary, built on Linux/BlueZ, that covers the whole BLE lifecycle (scan, enumerate, read/write/notify, fuzz, and structured assessment).

**How is it different from bettercap, gatttool, and hcitool?**
Those tools were never designed to work together and do not emit machine-readable output. Caeruleus consolidates the workflow into one binary with consistent commands, JSON/JSONL output, and no dependency hell.

**Can AI agents use Caeruleus?**
Yes. It emits token-efficient structured output and ships an Agent Skills-compatible skill teaching the command surface and methodology. In our benchmark, an agent using Caeruleus finished in 62% of the time and 70% of the tokens of free tool choice.

**What are the limitations?**
Central-only (not a peripheral); no traffic sniffing, active MITM, or peripheral cloning.

**How do I install it?**
`go install github.com/praetorian-inc/caeruleus/cmd/caeruleus@latest`, or grab a release binary. You need Linux with BlueZ and a BLE adapter; some raw-socket commands need root. Run `caeruleus doctor` first, then `caeruleus scan`.

## Contributing

Issues and pull requests are welcome, especially new `assess` workflows. Please run `make test` before opening a PR.

## Security

Caeruleus is designed for **authorized security testing only**. Only use it against devices you own or have explicit permission to assess; scanning, connecting to, and writing to BLE peripherals affects real hardware. 

## License

See [LICENSE](LICENSE).
