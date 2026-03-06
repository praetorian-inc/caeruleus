# Caeruleus

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
| `subscribe-notifications.ts` | Monitor notifications and indications |
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

## Prerequisites

- **Python 3.10+** with dependencies: `pip install -r skills/caeruleus/requirements.txt`
- **Node.js 20+** with dependencies: `cd skills/caeruleus && npm install`
- **BLE adapter** — built-in Bluetooth on macOS, or USB HCI adapter on Linux

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

| Platform | BLE Stack | Status |
|---|---|---|
| macOS | CoreBluetooth | Supported — uses UUID identifiers instead of MAC addresses |
| Linux | BlueZ | Supported — requires `hci0` or configured adapter |

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
