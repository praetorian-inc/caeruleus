# CaeruLEus

Caeruleus is a single Go binary (`caeruleus`) for the whole Bluetooth Low Energy assessment workflow on Linux/BlueZ: scan, enumerate, read/write/notify, fuzz, and structured security assessment. It talks to peripherals over BlueZ D-Bus and raw L2CAP/HCI sockets, and every command supports `-o json` for scripting, reporting, and LLM agents.

Instead of stitching together `bettercap`, `gatttool`, `bluetoothctl`, and one-off Bleak scripts, each with its own output format, Caeruleus handles the workflow from one command surface. No Python runtime, no MCP server, and it never shells out to other tools; all it needs is a BLE adapter and BlueZ. A portable [Agent Skill](https://agentskills.io) (`skills/caeruleus/`) drives the binary's JSON output into assessment workflows and reports.

*caeruleus*: Latin for "blue," with the LE capitalized for Low Energy.

## Layout

```
caeruleus/
├── cmd/caeruleus/        # main entrypoint (binary: caeruleus)
├── cmd/shell-harness/    # pty-driven tester for the interactive shell
├── internal/
│   ├── cli/              # cobra command tree (one file per command group)
│   ├── bluez/            # hand-rolled BlueZ D-Bus wrapper
│   ├── l2cap/            # raw L2CAP ATT socket
│   ├── smp/              # raw SMP over the HCI user channel (pairing feature exchange)
│   ├── hcimon/           # HCI monitor decode (notifications + connection params)
│   ├── bdaddr/           # adapter BD_ADDR read/spoof (vendor HCI)
│   └── fuzz/             # fuzzing: mutation engine, corpus, crash/hang triage
├── skills/caeruleus/     # the Go-driven Agent Skill (portable; agentskills.io format)
└── docs/                 # fuzzing-plan.md, ux-improvements.md
```

## Build

```bash
make build        # -> ./caeruleus
make test         # unit tests + shell tests
```

Or install the binary onto your `$PATH` directly with the Go toolchain:

```bash
go install github.com/praetorian-inc/caeruleus/cmd/caeruleus@latest
```

> Note: caeruleus targets Linux/BlueZ and does not build on macOS or Windows.

## Command groups

| Group | Commands |
|---|---|
| Discovery | `scan`, `enumerate`, `primary`, `characteristics` |
| GATT operations | `read`, `write`, `raw-write`, `listen`, `cccd`, `mtu` |
| Connection management | `pair`/`unpair`, `conn-params`, `disconnect`, `forget` |
| Scripting & automation | `shell`, `batch`, `serve`/`send` |
| Security assessment | `recon`, `assess check-auth`, `assess encryption`, `assess dfu`, `assess wwr` |
| Fuzzing | `fuzz write` (incl. `--raw`), `fuzz replay` |
| Adapter & diagnostics | `doctor`, `adapter`, `bdaddr`, `monitor` |

Every command takes `-b/--bdaddr`, `-i/--adapter`, `-t/--timeout`, and `-o/--format text|json|jsonl`. Assessment commands emit `{address, test, summary, findings[]}` with per-finding `severity`/`handle`/`uuid`/`evidence`. See [`skills/caeruleus/SKILL.md`](skills/caeruleus/SKILL.md) for the full reference and the recommended assessment methodology.

New to the tool, or coming from bettercap / gatttool / bluetoothctl / nRF Connect / custom Bleak scripts? Run `caeruleus recipes` for use-case-first examples, or see the [quick reference](docs/quick-reference.md), which maps those habits to caeruleus commands.

### Quick start

```bash
go install github.com/praetorian-inc/caeruleus/cmd/caeruleus@latest
caeruleus scan -d 6
caeruleus enumerate -b AA:BB:CC:DD:EE:FF --values     # full GATT tree + values
caeruleus recon -b AA:BB:CC:DD:EE:FF
caeruleus assess check-auth -b AA:BB:CC:DD:EE:FF -o json
sudo caeruleus conn-params -b AA:BB:CC:DD:EE:FF        # root: HCI monitor
```

Privileged commands (`conn-params`, `monitor`, `fuzz write --raw`, `cccd --raw`, `raw-write`, `mtu --set`, `bdaddr --set`) need root; see the skill doc for a scoped sudoers drop-in.

## Concurrency

BLE has a single active connection per peripheral, so interaction is sequential. Offline correlation/report steps that only read JSON artifacts can run in parallel.

## License

See [LICENSE](LICENSE).
