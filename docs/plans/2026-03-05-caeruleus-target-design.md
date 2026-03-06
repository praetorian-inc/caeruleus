# Caeruleus-Target: Vulnerable nRF52840 BLE Firmware Design

**Date:** 2026-03-05
**Status:** Approved
**Hardware:** nRF52840 DK (PCA10056)
**SDK:** nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0

## Purpose

Deliberately vulnerable BLE firmware for validating all caeruleus security testing capabilities. Every characteristic maps to a specific caeruleus flow so the full toolchain can be exercised against a known target.

---

## Section 1: GATT Profile

5 services, 14 characteristics total:

| Service | UUID | Purpose | Caeruleus Flows |
|---|---|---|---|
| Device Information | `0x180A` | Standard device info (manufacturer, firmware, hardware rev) | 1.4 Fingerprint, 1.5 Analyze Ads |
| Vulnerable Data | `0xBEEF` | Unprotected sensitive data (credentials, tokens, PII) | 1.3 Probe, 2.2 Encryption, 3.3 Auth Bypass |
| Command & Control | `0xC0DE` | Command interface with buffer overflow, replay vulnerabilities | 3.1 Fuzz, 3.5 Replay |
| Sensor Simulation | `0x5E45` | Notification-based sensor data (temp, humidity, battery) | 2.3 Subscribe, 3.8 Spoof |
| Nordic DFU | `0xFE59` | Unsigned firmware update (buttonless entry) | 3.7 DFU |

---

## Section 2: Characteristic Details

### Device Information Service (0x180A)

| Characteristic | UUID | Properties | Value |
|---|---|---|---|
| Manufacturer Name | `0x2A29` | Read | "Nordic Semiconductor" |
| Firmware Revision | `0x2A26` | Read | "1.0.0-vuln" |
| Hardware Revision | `0x2A27` | Read | "nRF52840 DK" |

### Vulnerable Data Service (0xBEEF)

| Characteristic | UUID | Properties | Vulnerability |
|---|---|---|---|
| Stored Credential | `0x0001` | Read | Unprotected read — returns plaintext "admin:password123" |
| Auth Token | `0x0002` | Read, Write | No input validation, accepts any length, no encryption required |
| Session Key | `0x0003` | Read, Write, WWR | Write-without-response enabled, no rate limiting |
| User PII | `0x0004` | Read | Returns "John Doe, john@example.com, 555-0123" without encryption |

### Command & Control Service (0xC0DE)

| Characteristic | UUID | Properties | Vulnerability |
|---|---|---|---|
| Command Input | `0x0001` | Write | No sequence number, no nonce — replay vulnerable |
| Command Response | `0x0002` | Read, Notify | Buffer overflow on writes >244 bytes → HardFault |
| Admin Control | `0x0003` | Read, Write | Accessible after unpairing — auth bypass |

### Sensor Simulation Service (0x5E45)

| Characteristic | UUID | Properties | Vulnerability |
|---|---|---|---|
| Temperature | `0x0001` | Read, Notify | Notification without encryption — MITM spoofable |
| Humidity | `0x0002` | Read, Notify | Same |
| Battery Level | `0x0003` | Read, Notify | Same |

### Nordic DFU Service (0xFE59)

| Characteristic | UUID | Properties | Vulnerability |
|---|---|---|---|
| DFU Control Point | `8ec90001-...` | Write, Notify | Accepts unsigned firmware |
| DFU Packet | `8ec90002-...` | Write WWR | No signature verification |
| Buttonless DFU | `8ec90003-...` | Write, Indicate | Unauthenticated entry to bootloader |

---

## Section 3: Security Configuration

### Pairing & Encryption

- **Pairing mode:** Just Works (no passkey, no OOB)
- **MITM protection:** Disabled (`SEC_MITM = 0`)
- **Legacy pairing:** Accepted (fallback from LE Secure Connections)
- **Encryption required:** No — all characteristics accessible without pairing
- **Bond storage:** Yes, but bonding not enforced for access

### Connection Parameters

| Parameter | Value | Weakness |
|---|---|---|
| Connection interval | 400ms | Slow — vulnerable to connection manipulation |
| Slave latency | 10 | High — device may miss commands |
| Supervision timeout | 800ms | Tight — easy to force disconnection |
| MTU | 247 | Standard |

### Crash & Recovery

- **Trigger:** Write >244 bytes to Command Response (0xC0DE/0x0002)
- **Behavior:** HardFault handler fires, logs crash reason to RAM
- **Recovery:** Watchdog timer (WDT) resets device after 2 seconds
- **Post-reset:** Device re-enters advertising, caeruleus reconnects

### DFU Bootloader

- **Signature validation:** Disabled (`NRF_DFU_REQUIRE_SIGNED_APP_UPDATE=0`)
- **Version rollback protection:** Disabled
- **Buttonless entry:** Enabled on 0xFE59/8ec90003, no authentication required
- **DFU transport:** BLE (Nordic Secure DFU protocol)

---

## Section 4: Build & Flash Instructions

### Project Structure

```
caeruleus-target/
├── config/
│   └── sdk_config.h          # SDK feature flags, BLE params, DFU settings
├── src/
│   ├── main.c                # Init, GATT services, event handlers
│   ├── services/
│   │   ├── vuln_data_svc.c   # Vulnerable Data Service (0xBEEF)
│   │   ├── cmd_ctrl_svc.c    # Command & Control Service (0xC0DE)
│   │   └── sensor_sim_svc.c  # Sensor Simulation Service (0x5E45)
│   └── crash_handler.c       # HardFault handler + watchdog recovery
├── dfu/
│   ├── bootloader/           # Secure bootloader (unsigned mode)
│   │   ├── main.c
│   │   └── dfu_public_key.c  # Dummy key (validation disabled)
│   └── settings/
│       └── bootloader_settings.hex
├── pca10056/                 # nRF52840 DK board files
│   └── s140/
│       ├── armgcc/
│       │   └── Makefile
│       └── ses/
│           └── caeruleus_target.emProject
├── keys/                     # DFU signing keys (test only)
│   ├── private.pem
│   └── public.pem
└── README.md
```

### Prerequisites

- ARM GCC 10.3 (`arm-none-eabi-gcc`)
- nRF5 SDK 17.1.0
- nRF Command Line Tools 10.x (`nrfjprog`, `mergehex`)
- nrfutil 6.x (DFU package generation)
- SoftDevice S140 v7.2.0

### Build & Flash

```bash
# 1. Flash SoftDevice (one-time)
nrfjprog --program s140_nrf52_7.2.0_softdevice.hex --chiperase -f nrf52
nrfjprog --reset -f nrf52

# 2. Build & flash bootloader (unsigned DFU)
cd dfu/bootloader/pca10056/armgcc
make
nrfjprog --program _build/nrf52840_xxAA_s140.hex --sectorerase -f nrf52

# 3. Generate bootloader settings
nrfutil settings generate --family NRF52840 \
  --application app.hex --application-version 1 \
  --bootloader-version 1 --bl-settings-version 2 \
  bootloader_settings.hex
nrfjprog --program bootloader_settings.hex --sectorerase -f nrf52

# 4. Build & flash application
cd pca10056/s140/armgcc
make
nrfjprog --program _build/nrf52840_xxAA_s140.hex --sectorerase -f nrf52
nrfjprog --reset -f nrf52
```

### DFU Package Creation

```bash
# Unsigned package (should be accepted — vulnerability)
nrfutil pkg generate --application app_v2.hex \
  --application-version 2 --hw-version 52 \
  --sd-req 0x0100 --no-key unsigned_dfu.zip

# Signed package (for comparison)
nrfutil pkg generate --application app_v2.hex \
  --application-version 2 --hw-version 52 \
  --sd-req 0x0100 --key-file keys/private.pem signed_dfu.zip

# Downgrade package (version 0 — should be rejected but won't be)
nrfutil pkg generate --application app_v1.hex \
  --application-version 0 --hw-version 52 \
  --sd-req 0x0100 --no-key downgrade_dfu.zip
```

---

## Section 5: Caeruleus Flow Test Matrix

| Caeruleus Flow | Script | Firmware Target | Expected Result |
|---|---|---|---|
| 1.1 Scan | `scan-devices.ts` | Adv at 100ms, name "Caeruleus-Target" | Device discovered with name, RSSI, mfr data |
| 1.2 Enumerate GATT | `enumerate-gatt.ts` | 5 services, 14 characteristics | Full GATT map |
| 1.3 Probe chars | `probe-characteristics.ts` | Mixed permissions | Identifies unprotected chars |
| 1.4 Fingerprint | `fingerprint-device.ts` | Nordic OUI, firmware "1.0.0-vuln" | Chipset + version identified |
| 1.5 Analyze ads | `analyze-advertisements.ts` | Nordic company ID 0x0059 | Manufacturer data parsed |
| 2.1 Test pairing | `test-pairing.ts` | Just Works, no MITM, legacy fallback | Pairing enforcement failure |
| 2.2 Test encryption | `test-encryption.ts` | No encryption on 0xBEEF | Encryption not required |
| 2.3 Subscribe notifications | `subscribe-notifications.ts` | Sensor sim notifies every 1s | Notifications received |
| 2.4 Audit GATT | `audit-gatt-profile.ts` | Missing CCCDs (intentional) | Spec violations flagged |
| 2.6 Analyze conn params | `analyze-connection-params.ts` | 400ms interval, 10 latency | Weak parameters flagged |
| 3.1 Fuzz | `fuzz-characteristic.ts` | >244B write → HardFault | Crash detected, WDT recovery |
| 3.2 Test WWR abuse | `test-wwr-abuse.ts` | Auth token accepts WWR | Rapid-fire writes succeed |
| 3.3 Auth bypass | `test-auth-bypass.ts` | Admin char post-unpair | Post-unpair access confirmed |
| 3.4 MITM relay | `mitm-relay.ts` | Just Works, no MITM flag | MITM relay established |
| 3.5 Replay writes | `replay-writes.ts` | No sequence number/nonce | Replayed commands execute |
| 3.7 Test DFU | `test-dfu.ts` | Unsigned bootloader, buttonless | Unsigned FW accepted |
| 3.8 Spoof notifications | `spoof-notifications.ts` | Sensor notifications via MITM | Spoofed values delivered |
| 4.1-4.6 Reporting | Phase 4 scripts | Offline JSON artifacts | Reports generated |

**14 characteristics across 5 services exercise all 18 caeruleus flows.**
