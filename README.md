# Caeruleus

Caeruleus is a hardware-agnostic BLE security testing toolkit for Linux/BlueZ, implemented as a single Go binary (`caeruleus`). It covers the full interaction-to-assessment lifecycle - scan, enumerate, read/write/notify, fuzzing, and structured security assessment - talking to peripherals directly over BlueZ D-Bus and raw L2CAP/HCI sockets. A portable [Agent Skill](https://agentskills.io) (`skills/caeruleus/`) orchestrates the binary's `-o json` output into assessment workflows and reports, and works with any Agent Skills-compatible agent.

*caeruleus* - Latin for "blue"

> The earlier proof-of-concept (a TypeScript + persistent-Python-server skill) has been superseded by this Go implementation. It remains recoverable in git history.

## Architecture

```
AI agent (Agent Skills)  ──drives──►  caeruleus skill (skills/caeruleus/SKILL.md)
                                      │  shells out, consumes -o json
                                      ▼
                         caeruleus (Go binary, this repo)
                          ├─ BlueZ D-Bus  (Adapter1/Device1/GattCharacteristic1)
                          ├─ raw L2CAP ATT socket (CID 0x0004) - root
                          └─ HCI monitor socket (btmon channel) - root
```

No Python, no MCP server, no sniffer/relay hardware, and no shelling out to other tools.

## Layout

```
caeruleus/
├── cmd/caeruleus/        # main entrypoint (binary: caeruleus)
├── cmd/shell-harness/    # pty-driven tester for the interactive shell
├── internal/
│   ├── cli/              # cobra command tree (one file per command group)
│   ├── bluez/            # hand-rolled BlueZ D-Bus wrapper
│   ├── l2cap/            # raw L2CAP ATT socket
│   ├── hcimon/           # HCI monitor decode (notifications + connection params)
│   ├── bdaddr/           # adapter BD_ADDR read/spoof (vendor HCI)
│   └── fuzz/             # fuzzing: mutation engine, corpus, crash/hang triage
├── skills/caeruleus/     # the Go-driven Agent Skill (portable; agentskills.io format)
├── caeruleus-target/     # deliberately-vulnerable nRF52840 DUT firmware
└── docs/                 # fuzzing-plan.md, ux-improvements.md
```

## Build

```bash
make build        # -> ./caeruleus
make test         # unit tests + shell tests
```

## Command groups

| Group | Commands |
|---|---|
| Discovery / interaction | `scan`, `enumerate`, `primary`, `characteristics`, `read`, `write`, `listen`, `cccd`, `mtu`, `shell`, `batch`, `serve`/`send` |
| Security assessment | `recon`, `assess auth-bypass`, `assess encryption`, `assess dfu`, `assess wwr`, `pair`/`unpair`, `conn-params` |
| Fuzzing | `fuzz write` (incl. `--raw`), `fuzz replay` |
| Adapter / diagnostics | `doctor`, `adapter`, `disconnect`, `forget`, `bdaddr`, `monitor`, `raw-write` |

Every command takes `-b/--bdaddr`, `-i/--adapter`, `-t/--timeout`, and `-o/--format text|json|jsonl`. Assessment commands emit `{address, test, summary, findings[]}` with per-finding `severity`/`handle`/`uuid`/`evidence`. See [`skills/caeruleus/SKILL.md`](skills/caeruleus/SKILL.md) for the full reference and the recommended assessment methodology.

### Quick start

```bash
make build
./caeruleus scan -t 6
./caeruleus recon -b AA:BB:CC:DD:EE:FF
./caeruleus assess auth-bypass -b AA:BB:CC:DD:EE:FF -o json
sudo ./caeruleus conn-params -b AA:BB:CC:DD:EE:FF        # root: HCI monitor
```

Privileged commands (`conn-params`, `monitor`, `fuzz write --raw`, `cccd --raw`, `raw-write`, `mtu --set`, `bdaddr --set`) need root; see the skill doc for a scoped sudoers drop-in.

## Caeruleus-Target (Vulnerable DUT Firmware)

The `caeruleus-target/` directory contains deliberately vulnerable nRF52840 BLE firmware for validating the toolkit. See [`caeruleus-target/README.md`](caeruleus-target/README.md) for build instructions and the full vulnerability matrix.

**GATT profile highlights:**
- Plaintext credentials and PII exposed over BLE
- No pairing or encryption enforcement
- Buffer overflow → HardFault on oversized writes
- No replay protection
- Unsigned DFU firmware acceptance

## Concurrency

BLE has a single active connection per peripheral, so interaction is sequential. Offline correlation/report steps that only read JSON artifacts can run in parallel.

## License

See [LICENSE](LICENSE).
