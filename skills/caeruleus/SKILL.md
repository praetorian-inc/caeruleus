---
name: caeruleus
description: Use when performing BLE security testing - device scanning, GATT enumeration, fuzzing, authentication bypass, MITM relay, DFU testing, and evidence capture via persistent Python server with TypeScript CLI wrappers.
allowed-tools: Bash, Read
---

# Caeruleus BLE Security Testing

**Direct BLE device security testing via persistent Python server with TypeScript CLI wrappers. No MCP server dependency.**

## When to Use

Use this skill when:

- Testing BLE devices during IoT security assessments
- Scanning for and enumerating BLE devices
- Probing GATT characteristics and permissions
- Fuzzing writable characteristics for crashes
- Testing pairing, encryption, and authentication bypass
- Performing MITM relay attacks via ESP32-Gattacker
- Testing Nordic DFU firmware update security
- Replaying captured write operations
- Generating security reports and remediation guidance

## Prerequisites

### System Requirements

- **Linux with BlueZ stack** (bluetoothctl, hcitool, hciconfig)
- **Python 3.10+** with `bleak`, `bluepy`, `pyyaml`, `scapy`
- **Node.js 20+** with `npx tsx` available
- **BLE adapter** (hci0 by default)

Install Python dependencies:
```bash
pip install -r requirements.txt
```

On Linux, ensure the Bluetooth service is running and the adapter is up before scanning:
```bash
sudo systemctl start bluetooth
sudo hciconfig hci0 up
```

### Optional Hardware

- **Ubertooth One** / **nRF52 Sniffer** / **Sniffle** — for passive BLE sniffing
- **ESP32-Gattacker** (ESP32-S3) — for MITM relay and notification spoofing

## Architecture

```
Claude Code Agent
    |
    v
TypeScript CLI Wrappers (*.ts)
    | stdin/stdout (YAML protocol)
    v
Persistent Python Server (caeruleus-server.py)
    |
    v
BlueZ / bleak / bluepy - BLE Device via HCI adapter

Optional:
caeruleus-sniffer.py - RF capture via Ubertooth/nRF52/Sniffle
ESP32-Gattacker      - MITM relay via WebSocket (ws://1.3.3.7/ws)
```

- **First call**: ~2-4 seconds (BLE adapter init)
- **Subsequent calls**: ~50-200ms (connection reuse)

## Available Tools

### Phase 1: Reconnaissance

| Wrapper | Purpose | Key Parameters |
| --- | --- | --- |
| `scan-devices` | Scan for BLE devices | `duration`, `adapter`, `active`, `target_mac` |
| `enumerate-gatt` | Enumerate GATT services/characteristics | `mac_address`, `mac_type` |
| `probe-characteristics` | Probe read/write permissions | `timeout_per_char` |
| `fingerprint-device` | Fingerprint chipset/firmware (offline) | `device_inventory_path` |
| `analyze-advertisements` | Analyze advertisement data (offline) | `device_inventory_path` |

### Phase 2: Protocol Analysis

| Wrapper | Purpose | Key Parameters |
| --- | --- | --- |
| `test-pairing` | Test pairing enforcement | `mac_address`, `test_enforcement`, `test_legacy_fallback` |
| `test-encryption` | Test encryption requirements | `mac_address` |
| `subscribe-notifications` | Monitor notifications/indications | `uuid`, `duration` |
| `audit-gatt-profile` | Audit GATT against BLE spec (offline) | `gatt_map_path` |
| `sniff-decode` | Capture & decode BLE packets | `target_mac`, `duration`, `mode` |
| `analyze-connection-params` | Analyze connection parameters | `mac_address` |

### Phase 3: Active Testing

| Wrapper | Purpose | Key Parameters |
| --- | --- | --- |
| `fuzz-characteristic` | Fuzz writable characteristics | `uuid`, `strategy`, `iterations` |
| `test-wwr-abuse` | Test write-without-response abuse | `uuids`, `rapid_fire_count`, `max_write_sizes` |
| `test-auth-bypass` | Test authentication bypass | `mac_address` |
| `replay-writes` | Replay captured write operations | `writes`, `unpair_before_replay` |
| `test-dfu` | Test Nordic DFU security | `mac_address`, `test_unsigned`, `test_buttonless` |
| `mitm-relay` | MITM relay via ESP32-Gattacker | `target_mac`, `enable_hooks`, `capture_duration_seconds` |
| `spoof-notifications` | Spoof notification values via MITM | `target_mac`, `spoofed_values` |
| `generate-fuzz-harness` | Generate fuzz test harness (offline) | `gatt_map_path` |

### Phase 4: Reporting & Evidence

| Wrapper | Purpose | Key Parameters |
| --- | --- | --- |
| `visualize-gatt` | Generate GATT hierarchy visualization (offline) | `gatt_map_path`, `format` |
| `correlate-findings` | Correlate findings across phases (offline) | `engagement_dir` |
| `map-cves` | Map chipset to known CVEs (offline) | `fingerprint_path` |
| `assemble-evidence` | Assemble evidence package (offline) | `engagement_dir` |
| `generate-remediation` | Generate remediation guide (offline) | `findings_path` |
| `generate-report` | Generate final security report (offline) | `engagement_dir` |

### Standalone Utilities

| Wrapper | Purpose | Key Parameters |
| --- | --- | --- |
| `read-characteristic` | Read a characteristic value | `uuid` |
| `write-characteristic` | Write to a characteristic | `uuid`, `value_hex` or `value_ascii`, `response` |
| `batch-read` | Read multiple characteristics in one session | `mac_address`, `uuids` or `reads` |
| `batch-write` | Write to multiple characteristics in one session | `mac_address`, `writes` (entries accept `value_hex` or `value_ascii`), `delay_ms` |
| `subscribe-raw` | Subscribe via raw L2CAP ATT socket (Linux) | `uuid`, `handle`, `write_value_hex`, `duration` |
| `raw-att` | Execute raw ATT operations (MTU exchange, handle read/write, listen) | `mac_address`, `operations` |
| `shutdown-server` | Gracefully stop the server (disconnects BLE first) | (none) |

**When to use `batch-write`:** Ideal for brute-force challenges or bulk operations — generate an array of writes with `read_after_write: true` to test value ranges (e.g., 0x00-0xFF) in a single persistent connection, far faster than individual write+read calls in a loop.

**When to use `subscribe-raw`:** Use when `subscribe-notifications` fails due to missing CCCD descriptors (common on CTF boards and non-compliant IoT firmware). Bypasses Bleak's D-Bus notification path and opens a direct L2CAP ATT socket. Also supports `subscribe-notifications` with `raw: true` to route through the same raw path with sensitive-data analysis. Note: raw subscribe disconnects Bleak temporarily; the server auto-reconnects afterward.

**When to use `raw-att`:** Use for ATT-level operations that Bleak doesn't expose — MTU negotiation (`exchange_mtu`), handle-level reads/writes by numeric handle, and passive ATT traffic listening. The `operations` array accepts a sequence of `exchange_mtu`, `read`, `write`, and `listen` operations executed in order over a single L2CAP socket. Like `subscribe-raw`, this disconnects Bleak temporarily and auto-reconnects afterward.

**NEVER use `pkill -f caeruleus-server` to stop the server.** Hard-killing the process leaves the BLE connection open at the BlueZ/kernel level, which blocks subsequent connections to single-connection devices (e.g., most BLE peripherals). Always use `shutdown-server` instead — it sends a BLE disconnect before exiting.

## Usage

### Scan for BLE Devices

```bash
npx tsx scan-devices.ts '{"duration": 15}'
npx tsx scan-devices.ts '{"duration": 10, "target_mac": "AA:BB:CC:DD:EE:FF"}'
```

### Enumerate GATT Services

```bash
npx tsx enumerate-gatt.ts '{"mac_address": "AA:BB:CC:DD:EE:FF"}'
```

### Fuzz a Characteristic

```bash
npx tsx fuzz-characteristic.ts '{"uuid": "2a00", "strategy": "boundary", "iterations": 500}'
```

### Test Pairing Security

```bash
npx tsx test-pairing.ts '{"mac_address": "AA:BB:CC:DD:EE:FF"}'
```

### MITM Relay via ESP32-Gattacker

Requires ESP32-Gattacker hardware on WiFi (default: ws://1.3.3.7/ws).
```bash
npx tsx mitm-relay.ts '{"target_mac": "AA:BB:CC:DD:EE:FF", "enable_hooks": true, "capture_duration_seconds": 120}'
```

### Test Nordic DFU Security

```bash
npx tsx test-dfu.ts '{"mac_address": "AA:BB:CC:DD:EE:FF"}'
```

**Important:** If the user asks to "test a BLE device" without specifying a target, first run `scan-devices` to show nearby devices and ask the user which MAC to target. Do not guess.

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `CAERULEUS_PYTHON` | `python3` | Python interpreter path |
| `CAERULEUS_ADAPTER` | `hci0` | BlueZ adapter |
| `CAERULEUS_TRANSPORT` | `usb` | Transport type |
| `CAERULEUS_DEVICE_ID` | (empty) | Specific adapter ID for multi-adapter |
| `CAERULEUS_SNIFFER_HARDWARE` | `ubertooth` | Sniffer hardware type |

## YAML Protocol

```yaml
# Request
id: 1
command: scan
params:
  duration: 10
  active: false
---

# Response (success)
id: 1
status: ok
result:
  device_count: 3
  devices: [...]
---

# Response (error)
id: 1
status: error
error:
  code: ADAPTER_NOT_FOUND
  message: "BlueZ adapter hci0 not found"
  recoverable: false
  suggestion: "Check adapter with: hciconfig"
---
```

## Troubleshooting

### Adapter Not Found

```
Error: ADAPTER_NOT_FOUND - BlueZ adapter hci0 not found
```

**Fix:** Verify adapter with `hciconfig`. If using a different adapter, set `CAERULEUS_ADAPTER=hci1`.

### Device Not Found

```
Error: DEVICE_NOT_FOUND - Target not in scan range
```

**Fix:** Run `scan-devices` to see nearby devices. Ensure target is powered on and advertising. If the device was previously connected, check for orphaned BlueZ connections (see below).

### Orphaned BlueZ Connection

If a wrapper process is killed (e.g. `pkill`, Ctrl-C on a background task) while the server holds a BLE connection, the kernel-level HCI link can survive even after the Python server exits. This blocks single-connection peripherals from advertising or accepting new connections.

**Diagnose:**
```bash
bluetoothctl devices Connected
```

**Fix:**
```bash
bluetoothctl disconnect <MAC>
```

**Root cause:** Killing the Node.js wrapper does not stop the detached Python server, and if Bleak is stuck (e.g. mid-`start_notify` on a CCCD-less device), `_cleanup_ble` previously hung on `_client.disconnect()` and never reached the `bluetoothctl` fallback. The server now applies a 5-second timeout to the Bleak disconnect to ensure the fallback always runs. **Always use `shutdown-server` instead of `pkill` to stop the server.**

### Connection Lost

```
Error: CONNECTION_LOST - BLE link dropped
```

**Fix:** The client auto-reconnects. If persistent, move closer to the device or check for interference.

### Device Crashed During Fuzz

```
Error: DEVICE_CRASHED - Target crashed during fuzz
```

**Fix:** Power-cycle the target device. The server auto-detects crash and waits for reconnection.

### ESP32-Gattacker Not Reachable

```
Error: WebSocket connection timeout
```

**Fix:** Ensure ESP32-Gattacker is powered on and connected to WiFi AP (ssid: ESP_WIFI, pass: gattattack). Web UI at http://1.3.3.7.

## Concurrency Rule

**Sequential when interacting with the DUT. Parallel only on offline artifacts.**

BLE has a single active connection — two operations simultaneously would corrupt state. Offline scripts (Phase 4) can run in parallel since they only read JSON artifacts.

## Integration

### Called By

- Manual invocation for BLE device security testing
- Skills requiring BLE runtime instrumentation

### Requires (invoke before starting)

None — Dependencies installed via `pip install -r requirements.txt` and `npm install`.

### Calls (during execution)

None — Terminal skill that provides BLE security testing capabilities.

### Pairs With (conditional)

| Skill | Trigger | Purpose |
| --- | --- | --- |
| `vault-finding` | When security issues found | Document findings from Caeruleus analysis |
| `plextrac-finding` | When reporting to PlexTrac | Create findings with evidence |

## References

- [README](README.md) - Development guide and testing instructions
- [Bluetooth Core Spec v5.3](https://www.bluetooth.com/specifications/specs/core-specification-5-3/) - BLE specification
- [bleak Documentation](https://bleak.readthedocs.io/) - Python BLE library
- [ESP32-Gattacker](https://github.com/p0px/ESP32-Gattacker) - MITM hardware firmware
