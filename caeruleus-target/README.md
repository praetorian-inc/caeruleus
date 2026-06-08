# Caeruleus-Target

Deliberately vulnerable nRF52840 BLE firmware for validating [caeruleus](../skills/caeruleus/) security testing capabilities.

**Hardware:** nRF52840 DK (PCA10056)
**SDK:** nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0

## GATT Profile

5 services, 14 characteristics:

| Service | UUID | Characteristics | Vulnerabilities |
|---|---|---|---|
| Device Information | `0x180A` | Manufacturer, Firmware Rev, Hardware Rev | Fingerprinting target |
| Vulnerable Data | `0xBEEF` | Credential, Auth Token, Session Key, PII | Plaintext creds, no validation, no encryption |
| Command & Control | `0xC0DE` | Command Input, Command Response, Admin | Replay, buffer overflow (HardFault), auth bypass |
| Sensor Simulation | `0x5E45` | Temperature, Humidity, Battery | Unencrypted notifications, MITM spoofable |
| Nordic DFU | `0xFE59` | Control Point, Packet, Buttonless | Unsigned FW, no rollback protection |

## Security Configuration (all deliberately weak)

- **Pairing:** Just Works (no passkey, no OOB, no MITM protection)
- **Encryption:** Not required on any characteristic
- **Legacy pairing:** Accepted (fallback from LE Secure Connections)
- **Connection params:** 400ms interval, 10 slave latency, 800ms supervision timeout
- **DFU:** Unsigned firmware accepted, version downgrade allowed

## Prerequisites

- ARM GCC 10.3+ (`arm-none-eabi-gcc`)
- [nRF5 SDK 17.1.0](https://www.nordicsemi.com/Products/Development-software/nRF5-SDK)
- [nRF Command Line Tools](https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools) (`nrfjprog`, `mergehex`)
- [nrfutil 6.x](https://github.com/NordicSemiconductor/pc-nrfutil) (DFU package generation)
- SoftDevice S140 v7.2.0 (included in SDK)

## Build & Flash

```bash
# Set SDK path
export SDK_ROOT=/path/to/nRF5_SDK_17.1.0_ddde560

# 1. Flash SoftDevice (one-time)
nrfjprog --program $SDK_ROOT/components/softdevice/s140/hex/s140_nrf52_7.2.0_softdevice.hex \
  --chiperase -f nrf52
nrfjprog --reset -f nrf52

# 2. Build application
cd pca10056/s140/armgcc
make

# 3. Flash application
nrfjprog --program _build/nrf52840_xxAA.hex --sectorerase -f nrf52
nrfjprog --reset -f nrf52
```

### DFU Bootloader (optional)

```bash
# Build & flash bootloader
cd dfu/bootloader/pca10056/armgcc
make
nrfjprog --program _build/nrf52840_xxAA_s140.hex --sectorerase -f nrf52

# Generate bootloader settings
nrfutil settings generate --family NRF52840 \
  --application _build/nrf52840_xxAA.hex --application-version 1 \
  --bootloader-version 1 --bl-settings-version 2 \
  bootloader_settings.hex
nrfjprog --program bootloader_settings.hex --sectorerase -f nrf52
nrfjprog --reset -f nrf52
```

### DFU Package Creation

```bash
# Unsigned package (accepted - vulnerability)
nrfutil pkg generate --application app.hex \
  --application-version 2 --hw-version 52 \
  --sd-req 0x0100 --no-key unsigned_dfu.zip

# Downgrade package (version 0 - accepted due to no rollback protection)
nrfutil pkg generate --application app.hex \
  --application-version 0 --hw-version 52 \
  --sd-req 0x0100 --no-key downgrade_dfu.zip
```

## Crash & Recovery

Writing >244 bytes to Command Response (`0xC0DE`/`0x0002`) triggers a buffer overflow → HardFault. The watchdog timer (2s) resets the device automatically. On reboot, the crash handler logs the fault registers via RTT and the device re-enters advertising.

## Caeruleus Flow Test Matrix

| Flow | Script | Expected Result |
|---|---|---|
| 1.1 Scan | `scan-devices.ts` | Discovers "Caeruleus-Target" with Nordic mfr data |
| 1.2 Enumerate GATT | `enumerate-gatt.ts` | 5 services, 14 characteristics |
| 1.3 Probe chars | `probe-characteristics.ts` | Identifies unprotected characteristics |
| 1.4 Fingerprint | `fingerprint-device.ts` | Nordic chipset, FW "1.0.0-vuln" |
| 1.5 Analyze ads | `analyze-advertisements.ts` | Nordic company ID 0x0059 decoded |
| 2.1 Test pairing | `test-pairing.ts` | Just Works, no MITM, legacy fallback |
| 2.2 Test encryption | `test-encryption.ts` | Encryption not required on 0xBEEF |
| 2.3 Subscribe | `subscribe-notifications.ts` | Sensor notifications every 1s |
| 2.4 Audit GATT | `audit-gatt-profile.ts` | Spec violations flagged |
| 2.6 Conn params | `analyze-connection-params.ts` | Weak parameters flagged |
| 3.1 Fuzz | `fuzz-characteristic.ts` | >244B → HardFault, WDT recovery |
| 3.2 WWR abuse | `test-wwr-abuse.ts` | Rapid-fire writes succeed |
| 3.3 Auth bypass | `test-auth-bypass.ts` | Post-unpair access confirmed |
| 3.4 MITM relay | `mitm-relay.ts` | Just Works enables MITM |
| 3.5 Replay | `replay-writes.ts` | No sequence/nonce, replayed cmds execute |
| 3.7 DFU | `test-dfu.ts` | Unsigned firmware accepted |
| 3.8 Spoof | `spoof-notifications.ts` | Spoofed sensor values delivered |
| 4.1-4.6 | Phase 4 scripts | Reports generated from offline artifacts |

## Project Structure

```
caeruleus-target/
├── config/
│   └── sdk_config.h              # SDK feature flags, BLE params, DFU settings
├── src/
│   ├── main.c                    # BLE init, GATT services, event handlers
│   ├── crash_handler.c/.h        # HardFault handler + WDT recovery
│   └── services/
│       ├── vuln_data_svc.c/.h    # Vulnerable Data (0xBEEF) - 4 chars
│       ├── cmd_ctrl_svc.c/.h     # Command & Control (0xC0DE) - 3 chars
│       └── sensor_sim_svc.c/.h   # Sensor Simulation (0x5E45) - 3 chars
├── dfu/
│   └── bootloader/
│       ├── main.c                # DFU bootloader (unsigned mode)
│       └── dfu_public_key.c      # Dummy key (validation disabled)
├── pca10056/s140/armgcc/
│   ├── Makefile                  # ARM GCC build
│   └── caeruleus_target.ld       # Linker script with .noinit section
├── keys/                         # DFU signing keys (test only)
└── README.md
```
