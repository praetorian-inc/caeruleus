# Caeruleus

NOTE: VERY EARLY STATE, SEVERAL FEATURES STILL UNTESTED. TALK TO AARON BEFORE USE

Caeruleus is a BLE security testing toolkit implemented as a [Claude Code](https://docs.anthropic.com/en/docs/claude-code) skill plugin — TypeScript scripts backed by a persistent Python server ([bleak](https://bleak.readthedocs.io/)) cover the full assessment lifecycle: recon, analysis, attack, and reporting. An AI agent orchestrates the tools against a target device through a shared YAML IPC client.

*caeruleus* — Latin for "blue"

## Architecture

```
Claude Code Agent
    │
    ▼
TypeScript CLI Wrappers (skills/caeruleus/*.ts)
    │ stdin/stdout YAML IPC
    ▼
Persistent Python Server (caeruleus-server.py)
    │
    ▼
bleak → CoreBluetooth (macOS) / BlueZ (Linux)

Optional:
  caeruleus-sniffer.py → Ubertooth / nRF52 / Sniffle
  ESP32-Gattacker      → MITM relay via WebSocket
```

The Python server is **persistent** — it stays alive across multiple commands within a session, reusing the BLE connection. First call takes ~2-4s (adapter init + connection), subsequent calls ~50-200ms.

### Raw ATT Operations (Linux only)

Two server commands bypass Bleak's D-Bus layer to operate directly on L2CAP ATT sockets:

- **`subscribe_raw`** — Opens a raw L2CAP ATT socket, optionally writes a trigger value (CCCD enable), and captures ATT Notification (0x1B) and Indication (0x1D) PDUs. Essential for devices that lack CCCD descriptors where Bleak's `start_notify` fails.
- **`raw_att`** — General-purpose raw ATT operations: `exchange_mtu`, `read`, `write`, `listen`. Enables MTU negotiation and reading/writing handles not present in Bleak's GATT cache (e.g., GAP service attributes hidden by BlueZ).

## Skill Scripts

### Phase 1: Reconnaissance

| Script | Purpose |
|---|---|
| `scan-devices.ts` | Discover BLE devices in range |
| `enumerate-gatt.ts` | Map GATT services, characteristics, descriptors |
| `probe-characteristics.ts` | Test actual read/write permissions |
| `fingerprint-device.ts` | Identify chipset, firmware, manufacturer |
| `analyze-advertisements.ts` | Decode advertisement and manufacturer data |

### Phase 2: Protocol Analysis

| Script | Purpose |
|---|---|
| `test-pairing.ts` | Test pairing enforcement and methods |
| `test-encryption.ts` | Test encryption requirements per characteristic |
| `subscribe-notifications.ts` | Monitor notifications and indications (supports `raw: true` for CCCD-less devices) |
| `subscribe-raw.ts` | Raw L2CAP ATT notification/indication capture (Linux, bypasses Bleak) |
| `audit-gatt-profile.ts` | Audit GATT profile against BLE spec |
| `sniff-decode.ts` | Capture and decode BLE packets |
| `analyze-connection-params.ts` | Analyze connection parameters |

### Phase 3: Active Testing

| Script | Purpose |
|---|---|
| `fuzz-characteristic.ts` | Fuzz writable characteristics for crashes |
| `test-wwr-abuse.ts` | Write-without-response overflow and rapid-fire |
| `test-auth-bypass.ts` | Test post-unpair and unauthenticated access |
| `replay-writes.ts` | Replay captured write sequences |
| `test-dfu.ts` | Test Nordic DFU firmware update security |
| `mitm-relay.ts` | MITM relay via ESP32-Gattacker |
| `spoof-notifications.ts` | Spoof notification values via MITM |
| `generate-fuzz-harness.ts` | Generate fuzz test harness from GATT map |

### Phase 4: Reporting

| Script | Purpose |
|---|---|
| `visualize-gatt.ts` | Generate GATT hierarchy visualization |
| `correlate-findings.ts` | Correlate findings across phases |
| `map-cves.ts` | Map chipset to known CVEs |
| `assemble-evidence.ts` | Assemble evidence package |
| `generate-remediation.ts` | Generate remediation guidance |
| `generate-report.ts` | Generate final security report |

### Standalone Utilities

| Script | Purpose |
|---|---|
| `read-characteristic.ts` | Read a single characteristic value |
| `write-characteristic.ts` | Write to a single characteristic |
| `batch-read.ts` | Read multiple characteristics in one session |
| `batch-write.ts` | Write to multiple characteristics with optional read-after-write |

## Prerequisites

- **Python 3.10+** with dependencies: `pip install -r skills/caeruleus/requirements.txt`
- **Node.js 20+** with dependencies: `cd skills/caeruleus && npm install`
- **BLE adapter** — built-in Bluetooth on macOS, or USB HCI adapter on Linux
- **Linux: BlueZ + Bluetooth service** — `sudo systemctl start bluetooth` (required for `hci0` adapter access)
- **Linux: `AF_BLUETOOTH` socket permissions** — raw L2CAP ATT operations (`subscribe_raw`, `raw_att`) require `CAP_NET_RAW` or membership in the `bluetooth` group. Verify with: `python3 -c "import socket; socket.socket(31, 5, 0).close(); print('OK')"`

### Optional Hardware

- **Ubertooth One** / **nRF52 Sniffer** / **Sniffle** — passive BLE sniffing
- **ESP32-Gattacker** (ESP32-S3) — MITM relay and notification spoofing

## Quick Start

```bash
# Install dependencies
cd skills/caeruleus
pip install -r requirements.txt
npm install

# Scan for devices
npx tsx scan-devices.ts '{"duration": 10}'

# Enumerate GATT on a target
npx tsx enumerate-gatt.ts '{"mac_address": "AA:BB:CC:DD:EE:FF"}'

# Fuzz a characteristic
npx tsx fuzz-characteristic.ts '{"mac_address": "AA:BB:CC:DD:EE:FF", "uuid": "2a00", "strategy": "boundary", "iterations": 100}'
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CAERULEUS_PYTHON` | `python3` | Python interpreter path |
| `CAERULEUS_ADAPTER` | `hci0` | BlueZ adapter (Linux only) |
| `CAERULEUS_TRANSPORT` | `usb` | Transport type |
| `CAERULEUS_SNIFFER_HARDWARE` | `ubertooth` | Sniffer hardware type |

## Platform Support

**Linux is required for full functionality.** macOS works for basic operations but has significant limitations due to CoreBluetooth's abstraction layer.

| Platform | BLE Stack | Status |
|---|---|---|
| Linux | BlueZ | **Full support** — recommended for engagements |
| macOS | CoreBluetooth | Partial — basic recon, reads, writes, and offline analysis work |

### macOS Limitations

CoreBluetooth abstracts the BLE stack and restricts low-level access:

- **No notification/indication support for non-compliant devices** — CoreBluetooth requires CCCD descriptors (0x2902) to be discoverable. Devices that omit CCCDs (common in CTF boards and some IoT firmware) cannot have notifications enabled.
- **GAP service hidden** — Generic Access (0x1800) and Generic Attribute (0x1801) services are managed internally by macOS and not exposed to applications. The Device Name characteristic (0x2A00) requires a platform-specific fallback.
- **No MAC address control** — CoreBluetooth uses randomized UUIDs instead of real MAC addresses. MAC spoofing is not possible.
- **No raw ATT handle writes** — only handles present in the discovered service tree can be accessed. Undiscovered handles (e.g., hidden CCCD descriptors) cannot be written to.
- **GATT cache persistence** — CoreBluetooth caches GATT data across connections. A Bluetooth power cycle (`blueutil --power 0 && blueutil --power 1`) may be needed to clear stale data.

## Caeruleus-Target (Vulnerable DUT Firmware)

The `caeruleus-target/` directory contains deliberately vulnerable nRF52840 BLE firmware for validating the toolkit. See [`caeruleus-target/README.md`](caeruleus-target/README.md) for build instructions and the full vulnerability matrix.

**GATT profile highlights:**
- Plaintext credentials and PII exposed over BLE
- No pairing or encryption enforcement
- Buffer overflow → HardFault on oversized writes
- No replay protection
- Unsigned DFU firmware acceptance

## Concurrency

**Sequential when interacting with the DUT. Parallel only on offline artifacts.**

BLE has a single active connection — concurrent operations would corrupt state. Phase 4 (reporting) scripts can run in parallel since they only read JSON artifacts.

## License

See [LICENSE](LICENSE).
