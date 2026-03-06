# BLE Security Testing Agents — Design Document

**Date:** 2026-03-05
**Project:** proteus-ble
**Status:** Draft

## Context

Praetorian consultants perform BLE security assessments on client IoT devices during time-boxed engagements. Current tooling includes Linux BlueZ stack (`bluetoothctl`, `gatttool`, `hcitool`, `bleak`/`bluepy`) and dedicated hardware (Ubertooth One, nRF52 dongles, Sniffle). Workflows are not standardized.

## Goals

- **Speed** — Compress manual BLE recon/testing from hours to minutes
- **Consistency** — Every engagement hits the same checklist regardless of operator
- **Depth** — Enable automated fuzzing and analysis impractical to do manually

## Integration Target

Claude Code skills/agents within the Chariot plugin ecosystem, following the `mobile:draco`/`mobile:malum` pattern (Python servers with TypeScript CLI wrappers).

## Build Order

Recon-first: Discovery → Protocol Analysis → Active Testing → Reporting

---

## Operator Interaction Patterns

BLE testing requires human-in-the-loop physical interactions. Three patterns handle this:

### Pattern: Fully Automated
No operator action needed. Agent runs autonomously given input parameters.

### Pattern: Prompt-and-Wait
Agent pauses, tells operator exactly what physical action is needed (e.g., "Put device into pairing mode"), waits for confirmation, then continues.

### Pattern: Prepare-Execute-Capture
Agent sets up all listeners/capture tooling first, then prompts operator to perform the physical action (e.g., "Initiate pairing from companion app now"), then captures and analyzes the result.

### Pattern: Async Choreography
Agent provides a step-by-step choreography document, kicks off background capture, operator follows steps independently. Agent processes results after sequence completes.

**Design rule:** The `ble-orchestrator` agent is the *only* agent that directly interacts with the operator. Phase agents send operator-action-needed requests up to the orchestrator, which serializes all human interaction in one place.

---

## Concurrency Rule

> **Sequential when interacting with the DUT. Parallel only when operating on offline artifacts (pcaps, GATT maps, logs).**

BLE has a single active connection — two agents writing simultaneously would corrupt state or cause disconnects. Phase agents execute sequentially through the DUT interaction phases. `ble-reporter` may run in parallel with upstream agents since it only consumes offline artifacts.

---

## Agent Architecture

| Agent | Role | Receives From | Sends To |
|-------|------|---------------|----------|
| `ble-orchestrator` | Coordinates full engagement, manages operator interaction, tracks progress | Operator (engagement scope) | All phase agents |
| `ble-recon` | Phase 1 — Discovery & Enumeration (flows 1.1–1.5) | Orchestrator (target params) | `ble-analyst`, `ble-attacker`, `ble-reporter` |
| `ble-analyst` | Phase 2 — Protocol Analysis (flows 2.1–2.6) | `ble-recon` (GATT map, device fingerprint) | `ble-attacker`, `ble-reporter` |
| `ble-attacker` | Phase 3 — Active Testing (flows 3.1–3.8) | `ble-recon` (GATT map), `ble-analyst` (security posture) | `ble-reporter` |
| `ble-reporter` | Phase 4 — Reporting & Evidence (flows 4.1–4.6) | All upstream agents (findings, artifacts) | Operator (deliverables) |

### Data Flow

```
                    ┌──────────────────┐
                    │  ble-orchestrator │
                    │  (operator-facing)│
                    └────────┬─────────┘
                             │ engagement scope
                             ▼
                    ┌──────────────────┐
                    │    ble-recon     │
                    │  1.1–1.5        │
                    └───┬──────┬──────┘
              GATT map  │      │  device fingerprint
                   ┌────▼──┐   │
                   │  ble-  │   │
                   │analyst │   │
                   │2.1–2.6 │   │
                   └──┬─────┘   │
        security      │        │
        posture  ┌────▼────────▼──┐
                 │  ble-attacker   │
                 │  3.1–3.8       │
                 └───────┬────────┘
                         │ all findings + artifacts
                    ┌────▼─────────┐
                    │ ble-reporter │
                    │ 4.1–4.6     │
                    └──────────────┘
```

---

## Phase 1: Discovery & Enumeration — `ble-recon`

| # | Flow | Pattern | Description |
|---|------|---------|-------------|
| 1.1 | BLE Device Discovery | Fully Automated | Runs passive scanning (`hcitool lescan`, `bluetoothctl scan`), collects advertisement data (device name, TX power, manufacturer data, service UUIDs), deduplicates, produces structured device inventory. Cross-references manufacturer IDs against Bluetooth SIG database and known-vulnerable device fingerprints. |
| 1.2 | Service & Characteristic Enumeration | Fully Automated | Connects to target device, walks full GATT table (services → characteristics → descriptors), records UUIDs, properties (read/write/notify), and handle values. Produces the structured GATT map consumed by all downstream agents. |
| 1.3 | Characteristic Probing | Fully Automated | For each characteristic: reads current values, checks which operations are actually permitted vs. advertised, identifies unauthenticated read/write access. Flags permission mismatches. |
| 1.4 | Device Fingerprinting | Fully Automated | Correlates advertisement data, GATT profile structure, and manufacturer OUI against known device databases to identify chipset, firmware version, and known CVEs. |
| 1.5 | Advertisement Data Analysis | Fully Automated | Parses raw advertisement/scan response payloads, decodes manufacturer-specific data fields, identifies information leakage (serial numbers, firmware versions, device state in cleartext). |

**Output artifacts:** Device inventory JSON, GATT map JSON, device fingerprint report, advertisement analysis report.

---

## Phase 2: Protocol Analysis — `ble-analyst`

| # | Flow | Pattern | Description |
|---|------|---------|-------------|
| 2.1 | Pairing & Bonding Analysis | Prepare-Execute-Capture | Determines pairing method (Just Works, Passkey, Numeric Comparison, OOB), tests whether pairing is required/enforced, checks for legacy pairing fallback, identifies IO capabilities mismatch exploitation. Agent sets up capture, prompts operator to trigger pairing from companion app. |
| 2.2 | Encryption Assessment | Prompt-and-Wait | Checks if link-layer encryption is enforced, tests for plaintext GATT access, identifies characteristics accessible without encryption, detects key size negotiation weaknesses (KNOB-style). Agent prompts operator to pair/unpair between encryption state tests. |
| 2.3 | Notification/Indication Traffic Analysis | Async Choreography | Subscribes to all notify/indicate characteristics, captures traffic over time, identifies data patterns, detects sensitive data in cleartext notifications (health data, location, credentials). Operator follows choreography to exercise device functions while agent captures. |
| 2.4 | GATT Profile Security Audit | Fully Automated | Maps each characteristic against Bluetooth SIG standard profiles, identifies deviations from spec, flags custom services for deeper analysis, checks for hidden/undocumented characteristics. |
| 2.5 | Passive BLE Sniffing & Decode | Async Choreography | Orchestrates Ubertooth/Sniffle/nRF Sniffer to capture over-the-air packets, decodes LL and ATT layers, reconstructs GATT conversations, identifies unencrypted traffic. Agent starts sniffer, gives operator choreography for normal device usage. |
| 2.6 | Connection Parameter Analysis | Fully Automated | Examines connection intervals, slave latency, supervision timeout, MTU negotiation. Identifies configurations that weaken security or enable DoS. |

**Output artifacts:** Pairing analysis report, encryption assessment, traffic captures (pcap), GATT security audit, connection parameter report.

---

## Phase 3: Active Testing — `ble-attacker`

| # | Flow | Pattern | Description |
|---|------|---------|-------------|
| 3.1 | GATT Fuzzing Harness Generation | Fully Automated | For each writable characteristic: generates type-aware fuzz inputs based on expected format (UUID type, descriptor hints, observed values), produces reusable fuzzing harness scripts. Consumes GATT map from 1.2. |
| 3.2 | Characteristic Fuzzing Execution | Prompt-and-Wait | Executes generated harnesses, monitors for crashes/hangs/unexpected responses, logs anomalies with exact triggering input. Pauses if device crashes for operator power-cycle. |
| 3.3 | Write-Without-Response Abuse | Fully Automated | Tests all characteristics supporting write-without-response for: buffer overflow via oversized writes, rapid-fire writes for resource exhaustion, out-of-range value injection. |
| 3.4 | MITM / Relay Attack | Prepare-Execute-Capture | Sets up GATTacker/BtleJuice MITM relay between companion app and device. Agent configures proxy, prompts operator for physical placement, captures and decodes proxied GATT traffic, identifies modifiable values in transit. |
| 3.5 | Replay Attack Testing | Prepare-Execute-Capture | Captures authenticated write sequences (prompts operator to perform normal action via app), then replays after unpairing/re-pairing. Tests whether device accepts stale commands — identifies missing replay protection. |
| 3.6 | Authentication Bypass Testing | Prompt-and-Wait | Systematically tests: accessing protected characteristics without pairing, with legacy pairing, with manipulated IO capabilities, with stolen/replayed LTK. Operator may need to pair/unpair between tests. |
| 3.7 | Firmware Update Mechanism Testing | Async Choreography | If DFU service detected (Nordic DFU, TI OAD, etc.): tests for unsigned firmware acceptance, version downgrade, partial update handling. Agent provides step sequence, operator triggers DFU mode on device. |
| 3.8 | Notification Spoofing / Injection | Prepare-Execute-Capture | Clones device's GATT profile, advertises as the target device, tests whether companion app validates device identity, injects crafted notification data. Agent sets up spoofed peripheral, prompts operator to connect companion app. |

**Output artifacts:** Fuzzing harness scripts, crash logs, MITM traffic captures, replay test results, auth bypass results, DFU analysis, spoofing results.

---

## Phase 4: Reporting & Evidence Collection — `ble-reporter`

| # | Flow | Pattern | Description |
|---|------|---------|-------------|
| 4.1 | GATT Map Visualization | Fully Automated | Generates visual representation of full GATT hierarchy annotated with properties, permissions, and security findings from other phases. |
| 4.2 | Finding Correlation & Deduplication | Fully Automated | Aggregates findings across all agents, deduplicates, correlates related issues into attack chains, assigns severity ratings. |
| 4.3 | CVE & Known Vulnerability Mapping | Fully Automated | Maps identified chipset/firmware to known CVEs via NVD/CCVERA integration. Distinguishes known issues from novel findings. |
| 4.4 | Evidence Package Assembly | Fully Automated | Assembles pcaps, GATT dumps, fuzz logs, and crash dumps into structured evidence package with chain-of-custody metadata (timestamps, tool versions, commands run). |
| 4.5 | Remediation Guidance Generation | Fully Automated | For each finding: generates remediation recommendations referencing Bluetooth SIG best practices, maps to relevant BLE spec sections, suggests implementation-level fixes. |
| 4.6 | Engagement Summary Report | Prompt-and-Wait | Produces structured engagement summary: scope, methodology, findings by severity, attack chain narratives, remediation roadmap. Agent drafts, operator reviews before finalizing. |

**Output artifacts:** GATT map diagrams, correlated findings database, CVE mapping report, evidence package (ZIP), remediation guide, final engagement report.

---

## Summary Statistics

- **Total flows:** 25
- **Agents:** 5 (1 orchestrator + 4 phase agents)
- **Fully Automated:** 14 flows
- **Prompt-and-Wait:** 5 flows
- **Prepare-Execute-Capture:** 4 flows
- **Async Choreography:** 3 flows (1 shared)

### Design Amendments (from review)

1. **Security posture generation**: `ble-analyst` explicitly produces `analysis/security-posture.json` as its final step after all 2.x flows complete. This is the key handoff artifact consumed by `ble-attacker`.
2. **Finding ID namespacing**: Finding IDs are agent-prefixed to avoid collisions: `F-recon-001`, `F-analyst-001`, `F-atk-001`.
3. **Reporter atomicity**: `ble-reporter` only reads upstream artifacts with completion markers. Agents write a `_complete` sentinel file (e.g., `recon/_complete`) after all flows in a phase finish. Reporter checks for this before reading.
4. **Schema versioning**: All schemas (including `engagement.json` and `operator-log.json`) include `schema_version: "1.0"`.
5. **Reconnection strategy**: `proteus-ble-server.py` auto-reconnects on connection loss via `_ensure_connected()`. The TS client auto-restarts the server process on crash. `BleakClient.set_disconnected_callback` logs disconnects for evidence.

---

## Inter-Agent Data Transfer Scheme

Data flows between agents via **file-based persistence** in a shared engagement directory, following the `persisting-agent-outputs` pattern. Each engagement gets its own directory; agents read upstream artifacts and write downstream artifacts to known paths.

### Engagement Directory Layout

```
.claude/.output/ble-engagements/{timestamp}-{target-slug}/
├── MANIFEST.yaml                          # Engagement metadata + agent coordination
├── config/
│   └── engagement.json                    # Engagement scope & target parameters
├── recon/                                 # ble-recon outputs (Phase 1)
│   ├── device-inventory.json              # 1.1 — All discovered devices
│   ├── gatt-map.json                      # 1.2 — Full GATT hierarchy per device
│   ├── characteristic-probes.json         # 1.3 — Permission test results
│   ├── device-fingerprint.json            # 1.4 — Chipset/firmware/CVE matches
│   └── advertisement-analysis.json        # 1.5 — Decoded advertisement data
├── analysis/                              # ble-analyst outputs (Phase 2)
│   ├── pairing-analysis.json              # 2.1 — Pairing method assessment
│   ├── encryption-assessment.json         # 2.2 — Encryption enforcement results
│   ├── notification-traffic.json          # 2.3 — Captured notification data
│   ├── gatt-security-audit.json           # 2.4 — Spec compliance findings
│   ├── captures/                          # 2.5 — Raw packet captures
│   │   └── *.pcap
│   ├── sniff-decode.json                  # 2.5 — Decoded sniff summary
│   ├── connection-params.json             # 2.6 — Connection parameter analysis
│   └── security-posture.json              # Aggregated Phase 2 summary
├── attacks/                               # ble-attacker outputs (Phase 3)
│   ├── harnesses/                         # 3.1 — Generated fuzzing scripts
│   │   └── fuzz-{service}-{char}.py
│   ├── fuzz-results.json                  # 3.2 — Fuzzing execution results
│   ├── wwr-abuse-results.json             # 3.3 — Write-without-response results
│   ├── mitm-results.json                  # 3.4 — MITM/relay findings
│   ├── replay-results.json                # 3.5 — Replay attack results
│   ├── auth-bypass-results.json           # 3.6 — Auth bypass test results
│   ├── dfu-analysis.json                  # 3.7 — Firmware update findings
│   ├── spoofing-results.json              # 3.8 — Notification spoofing results
│   └── captures/                          # Raw attack traffic
│       └── *.pcap
├── reports/                               # ble-reporter outputs (Phase 4)
│   ├── gatt-map-visual.svg                # 4.1 — GATT visualization
│   ├── correlated-findings.json           # 4.2 — Deduplicated, correlated findings
│   ├── cve-mapping.json                   # 4.3 — CVE cross-references
│   ├── evidence/                          # 4.4 — Evidence package
│   │   ├── evidence-manifest.json
│   │   └── evidence-package.zip
│   ├── remediation-guide.md               # 4.5 — Remediation recommendations
│   └── engagement-report.md               # 4.6 — Final summary report
└── operator-log.json                      # Timestamped log of all operator interactions
```

### Data Dependency Graph

```
engagement.json ──────────────────────────────────────────────┐
     │                                                         │
     ▼                                                         │
device-inventory.json (1.1) ──┬──▶ device-fingerprint.json    │
     │                        │         (1.4)                  │
     │                        └──▶ advertisement-analysis.json │
     │                                  (1.5)                  │
     ▼                                                         │
gatt-map.json (1.2) ─────────────────────────────────────┐    │
     │                                                    │    │
     ▼                                                    │    │
characteristic-probes.json (1.3)                          │    │
     │                                                    │    │
     ├──▶ pairing-analysis.json (2.1)                     │    │
     ├──▶ encryption-assessment.json (2.2)                │    │
     ├──▶ notification-traffic.json (2.3)                 │    │
     ├──▶ gatt-security-audit.json (2.4)                  │    │
     ├──▶ sniff-decode.json (2.5)                         │    │
     └──▶ connection-params.json (2.6)                    │    │
              │                                           │    │
              ▼                                           │    │
     security-posture.json (2.x) ────────────────────┐   │    │
              │                                      │   │    │
              ├──▶ fuzz harnesses (3.1) ◀────────────┼───┘    │
              ├──▶ fuzz-results.json (3.2)           │        │
              ├──▶ wwr-abuse-results.json (3.3)      │        │
              ├──▶ mitm-results.json (3.4)           │        │
              ├──▶ replay-results.json (3.5)         │        │
              ├──▶ auth-bypass-results.json (3.6)    │        │
              ├──▶ dfu-analysis.json (3.7)           │        │
              └──▶ spoofing-results.json (3.8)       │        │
                         │                           │        │
                         ▼ (all findings)            │        │
              correlated-findings.json (4.2) ◀───────┘        │
                         │                                    │
                         ├──▶ cve-mapping.json (4.3) ◀────────┘
                         ├──▶ gatt-map-visual.svg (4.1)
                         ├──▶ evidence-package.zip (4.4)
                         ├──▶ remediation-guide.md (4.5)
                         └──▶ engagement-report.md (4.6)
```

### Core Data Schemas

#### Engagement Config (input to all agents)

```json
{
  "schema_version": "1.0",
  "engagement_id": "eng-2026-03-05-smartlock",
  "target": {
    "device_name": "SmartLock Pro v2",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "mac_type": "public|random",
    "known_services": ["0x1800", "0x1801"],
    "companion_app": {
      "platform": "android|ios|both",
      "package": "com.vendor.smartlock"
    }
  },
  "scope": {
    "phases": [1, 2, 3, 4],
    "excluded_flows": [],
    "hardware_available": ["ubertooth", "nrf52", "sniffle"],
    "adapter": "hci0",
    "time_budget_minutes": 480
  },
  "operator": {
    "name": "Aaron Wasserman",
    "engagement_ref": "PRAET-2026-0312"
  }
}
```

#### Device Inventory (1.1 → consumed by all downstream)

```json
{
  "schema_version": "1.0",
  "scan_timestamp": "2026-03-05T14:30:00Z",
  "scan_duration_seconds": 60,
  "adapter": "hci0",
  "devices": [
    {
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "mac_type": "public",
      "device_name": "SmartLock Pro v2",
      "rssi_dbm": -45,
      "tx_power_dbm": 4,
      "connectable": true,
      "service_uuids": ["0x1800", "0xFFF0"],
      "manufacturer_data": {
        "company_id": "0x0059",
        "company_name": "Nordic Semiconductor",
        "raw_hex": "0201061107...",
        "decoded": {}
      },
      "scan_response": {
        "raw_hex": "0809536d617274...",
        "decoded_fields": {}
      },
      "flags": ["LE General Discoverable", "BR/EDR Not Supported"],
      "appearance": "0x0000",
      "first_seen": "2026-03-05T14:30:02Z",
      "last_seen": "2026-03-05T14:30:58Z",
      "advertisement_count": 47,
      "is_target": true
    }
  ]
}
```

#### GATT Map (1.2 → the most critical shared artifact)

This is the backbone schema — Phase 2, 3, and 4 all consume it.

```json
{
  "schema_version": "1.0",
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "connection_timestamp": "2026-03-05T14:32:00Z",
  "mtu": 247,
  "services": [
    {
      "uuid": "00001800-0000-1000-8000-00805f9b34fb",
      "uuid_short": "0x1800",
      "name": "Generic Access",
      "type": "standard|custom",
      "handle_start": "0x0001",
      "handle_end": "0x0009",
      "characteristics": [
        {
          "uuid": "00002a00-0000-1000-8000-00805f9b34fb",
          "uuid_short": "0x2A00",
          "name": "Device Name",
          "handle": "0x0003",
          "value_handle": "0x0004",
          "properties": {
            "broadcast": false,
            "read": true,
            "write_no_response": false,
            "write": false,
            "notify": false,
            "indicate": false,
            "authenticated_signed_writes": false,
            "extended_properties": false
          },
          "security": {
            "read_requires": "none|encryption|authentication",
            "write_requires": "none|encryption|authentication"
          },
          "value": {
            "raw_hex": "536d6172744c6f636b",
            "decoded": "SmartLock",
            "encoding": "utf-8"
          },
          "descriptors": [
            {
              "uuid": "0x2902",
              "name": "Client Characteristic Configuration",
              "handle": "0x0005",
              "value_hex": "0000"
            }
          ]
        }
      ]
    }
  ],
  "summary": {
    "total_services": 5,
    "standard_services": 3,
    "custom_services": 2,
    "total_characteristics": 18,
    "readable": 14,
    "writable": 7,
    "notifiable": 4,
    "indicatable": 1
  }
}
```

#### Unified Finding Format (produced by Phases 1–3, consumed by Phase 4)

Every agent that discovers a security issue writes findings in this format. The reporter agent aggregates all of them.

```json
{
  "finding_id": "F-2026-0305-001",
  "source_flow": "3.6",
  "source_agent": "ble-attacker",
  "timestamp": "2026-03-05T16:45:00Z",
  "severity": "critical|high|medium|low|informational",
  "cvss_v3_score": 8.1,
  "cvss_v3_vector": "AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "title": "Unauthenticated Write to Door Lock Characteristic",
  "category": "authentication|encryption|information_disclosure|injection|denial_of_service|firmware|replay|spoofing|configuration",
  "affected_characteristic": {
    "service_uuid": "0xFFF0",
    "characteristic_uuid": "0xFFF1",
    "handle": "0x0012",
    "name": "Lock Control"
  },
  "description": "The lock control characteristic (0xFFF1) accepts write commands without requiring pairing or encryption. An attacker within BLE range can unlock the device by writing 0x01 to handle 0x0012.",
  "reproduction": {
    "prerequisites": ["BLE adapter in range", "Device powered on"],
    "steps": [
      "gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0012 -n 01",
      "Observe door lock actuator engage"
    ],
    "interaction_pattern": "fully_automated",
    "operator_actions": []
  },
  "evidence": {
    "pcap_file": "attacks/captures/auth-bypass-001.pcap",
    "screenshots": [],
    "logs": ["attacks/auth-bypass-results.json"],
    "raw_request_hex": "01",
    "raw_response_hex": "00",
    "tool_used": "gatttool",
    "tool_command": "gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0012 -n 01"
  },
  "related_findings": ["F-2026-0305-003"],
  "attack_chain": {
    "position": 1,
    "chain_id": "AC-001",
    "chain_description": "Unauthenticated unlock → firmware downgrade → persistent backdoor",
    "next_finding": "F-2026-0305-003"
  },
  "cve_references": [],
  "remediation": {
    "short_term": "Require encryption for all writes to 0xFFF1",
    "long_term": "Implement application-layer authentication with challenge-response",
    "ble_spec_reference": "Core Spec v5.3, Vol 3, Part C, Section 10.3"
  }
}
```

#### Security Posture Summary (produced by ble-analyst, consumed by ble-attacker)

Key handoff between Phase 2 and Phase 3 — tells the attacker where to focus.

```json
{
  "schema_version": "1.0",
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "assessment_timestamp": "2026-03-05T15:45:00Z",
  "pairing": {
    "method": "just_works",
    "enforced": false,
    "legacy_fallback": true,
    "mitm_protection": false
  },
  "encryption": {
    "link_layer_enforced": false,
    "min_key_size": 7,
    "characteristics_unencrypted": ["0xFFF1", "0xFFF2", "0xFFF3"],
    "knob_susceptible": true
  },
  "authentication": {
    "app_layer_auth": false,
    "challenge_response": false,
    "token_based": false
  },
  "attack_surface_priority": [
    {
      "characteristic_uuid": "0xFFF1",
      "handle": "0x0012",
      "risk": "critical",
      "rationale": "Writable without pairing or encryption, controls lock actuator",
      "recommended_attacks": ["3.3", "3.6", "3.2"]
    },
    {
      "characteristic_uuid": "0xFFF2",
      "handle": "0x0015",
      "risk": "high",
      "rationale": "Accepts write-without-response, unknown function, no input validation observed",
      "recommended_attacks": ["3.3", "3.2"]
    }
  ],
  "dfu_detected": {
    "present": true,
    "type": "nordic_dfu",
    "service_uuid": "0xFE59",
    "secured": false
  },
  "overall_risk": "critical",
  "summary": "Device uses Just Works pairing without enforcement. Link-layer encryption is not required. Three custom characteristics are accessible without any authentication. DFU service present and unsigned."
}
```

#### Operator Interaction Log (maintained by ble-orchestrator)

Records every human-in-the-loop interaction for evidence and reproducibility. Includes `schema_version` for forward compatibility.

```json
{
  "schema_version": "1.0",
  "engagement_id": "eng-2026-03-05-smartlock",
  "interactions": [
    {
      "interaction_id": "OP-001",
      "timestamp": "2026-03-05T15:10:00Z",
      "requesting_agent": "ble-analyst",
      "requesting_flow": "2.1",
      "pattern": "prepare_execute_capture",
      "phase": "prepare",
      "request": "Capture tooling ready. Please initiate pairing from the SmartLock companion app now.",
      "operator_response": "confirmed",
      "response_timestamp": "2026-03-05T15:10:45Z",
      "notes": ""
    },
    {
      "interaction_id": "OP-002",
      "timestamp": "2026-03-05T16:30:00Z",
      "requesting_agent": "ble-attacker",
      "requesting_flow": "3.2",
      "pattern": "prompt_and_wait",
      "phase": "pause",
      "request": "Device appears to have crashed during fuzzing of 0xFFF2 (input: 0xFFFFFFFF). Please power-cycle the device and confirm.",
      "operator_response": "confirmed",
      "response_timestamp": "2026-03-05T16:32:12Z",
      "notes": "Device LED was off, had to pull battery"
    }
  ]
}
```

### Agent-to-Artifact Dependency Matrix

| Agent | Reads | Writes |
|-------|-------|--------|
| `ble-orchestrator` | `engagement.json` | `operator-log.json`, `MANIFEST.yaml` |
| `ble-recon` | `engagement.json` | `recon/*.json` |
| `ble-analyst` | `engagement.json`, `recon/gatt-map.json`, `recon/device-inventory.json`, `recon/characteristic-probes.json`, `recon/device-fingerprint.json` | `analysis/*.json`, `analysis/captures/*.pcap` |
| `ble-attacker` | `engagement.json`, `recon/gatt-map.json`, `analysis/security-posture.json` | `attacks/*.json`, `attacks/harnesses/*.py`, `attacks/captures/*.pcap` |
| `ble-reporter` | All `recon/*.json`, `analysis/*.json`, `attacks/*.json` | `reports/*` |

### Schema Versioning

All JSON schemas include a `schema_version` field. Agents check version compatibility on read:
- Same major version → compatible
- Different major version → abort with error, request operator intervention

---

---

## Implementation Architecture

### Decision: Hybrid — Persistent BLE Server + Discrete Analysis Scripts

**Rationale:** Unlike Frida (which has `frida-node` as an alternative), the BLE ecosystem is Python-only (`bleak`, `bluepy`, `scapy`, Ubertooth bindings). The Python server is a requirement, not a choice. Session reuse is critical — BLE connection establishment takes 3–15s, and most flows require an active connection. YAML-over-stdin/stdout IPC protocol chosen for ecosystem consistency with malum/draco.

### Two-Process Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    proteus-ble-server.py                         │
│           (persistent, holds BLE connection state)           │
│                                                              │
│  BLE Connection Commands:                                    │
│    scan, connect, disconnect, read_char, write_char,         │
│    subscribe, unsubscribe, pair, unpair, get_gatt_map,       │
│    probe_permissions, start_fuzz, write_no_response           │
│                                                              │
│  Persistent State:                                           │
│    - Active BLE connection (bleak.BleakClient)               │
│    - Pairing state & encryption status                       │
│    - Notification buffer (async callback accumulator)        │
│    - Discovered GATT map cache                               │
│    - Device capabilities & MTU                               │
│                                                              │
│  Libraries: bleak, bluepy (fallback), scapy                  │
└──────────────────────────┬──────────────────────────────────┘
                           │ YAML over stdin/stdout
                           │ (same protocol as malum/draco)
┌──────────────────────────▼──────────────────────────────────┐
│              TypeScript CLI Wrappers                          │
│                                                              │
│  Online (require server):          Offline (standalone):     │
│    scan-devices.ts                   fingerprint-device.ts   │
│    enumerate-gatt.ts                 analyze-advertisements.ts│
│    probe-characteristics.ts          audit-gatt-profile.ts   │
│    read-characteristic.ts            generate-fuzz-harness.ts│
│    write-characteristic.ts           correlate-findings.ts   │
│    subscribe-notifications.ts        map-cves.ts             │
│    test-pairing.ts                   generate-report.ts      │
│    test-encryption.ts                visualize-gatt.ts       │
│    fuzz-characteristic.ts            assemble-evidence.ts    │
│    replay-writes.ts                                          │
│                                                              │
│  Shared: lib/client.ts, lib/types.ts, lib/errors.ts         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              proteus-ble-sniffer.py (optional, Phase 2+)         │
│         (separate persistent server for RF hardware)         │
│                                                              │
│  Commands: start_capture, stop_capture, decode_packets       │
│  Hardware: Ubertooth, nRF52 Sniffer, Sniffle                │
│  Rationale: Separate process because RF sniffing uses        │
│  different hardware/adapters than GATT interaction.           │
│  Avoids multiplexing BlueZ and Ubertooth in one process.     │
└─────────────────────────────────────────────────────────────┘
```

### Flow-to-Architecture Mapping

| Flow | Architecture | Rationale |
|------|-------------|-----------|
| 1.1 BLE Device Discovery | **Server** — `scan` command | Needs adapter access via bleak |
| 1.2 Service & Char Enumeration | **Server** — `connect` + `get_gatt_map` | Needs active connection |
| 1.3 Characteristic Probing | **Server** — `probe_permissions` | Needs active connection, iterates all chars |
| 1.4 Device Fingerprinting | **Offline** — `fingerprint-device.ts` | Reads device-inventory.json, cross-refs databases |
| 1.5 Advertisement Analysis | **Offline** — `analyze-advertisements.ts` | Parses saved advertisement data |
| 2.1 Pairing Analysis | **Server** — `pair` + `test_pairing` | Needs active connection, modifies pairing state |
| 2.2 Encryption Assessment | **Server** — `test_encryption` | Needs connection, toggles encryption states |
| 2.3 Notification Traffic | **Server** — `subscribe` (long-running) | Needs persistent connection for async notifications |
| 2.4 GATT Profile Audit | **Offline** — `audit-gatt-profile.ts` | Reads gatt-map.json, cross-refs BT SIG specs |
| 2.5 Passive Sniffing | **Sniffer server** — `start_capture` | Separate hardware (Ubertooth/Sniffle) |
| 2.6 Connection Params | **Server** — `get_connection_params` | Needs active connection |
| 3.1 Fuzz Harness Gen | **Offline** — `generate-fuzz-harness.ts` | Reads gatt-map.json, generates Python scripts |
| 3.2 Fuzz Execution | **Server** — `fuzz_characteristic` | Needs active connection, monitors for crashes |
| 3.3 WWR Abuse | **Server** — `write_no_response` | Needs active connection |
| 3.4 MITM/Relay | **Server** — orchestrates GATTacker | Needs adapter for relay setup |
| 3.5 Replay Attack | **Server** — `replay_writes` | Needs active connection |
| 3.6 Auth Bypass | **Server** — `test_auth_bypass` | Needs connection, modifies pairing state |
| 3.7 DFU Testing | **Server** — `test_dfu` | Needs active connection to DFU service |
| 3.8 Notification Spoofing | **Server** — `spoof_peripheral` | Needs adapter to advertise as fake device |
| 4.1 GATT Visualization | **Offline** — `visualize-gatt.ts` | Reads gatt-map.json |
| 4.2 Finding Correlation | **Offline** — `correlate-findings.ts` | Reads all findings JSONs |
| 4.3 CVE Mapping | **Offline** — `map-cves.ts` | Reads device-fingerprint.json, queries NVD/CCVERA |
| 4.4 Evidence Assembly | **Offline** — `assemble-evidence.ts` | Reads all artifacts |
| 4.5 Remediation Guide | **Offline** — `generate-remediation.ts` | Reads correlated findings |
| 4.6 Engagement Report | **Offline** — `generate-report.ts` | Reads all upstream artifacts |

**Split:** 15 server commands, 10 offline scripts, 1 sniffer server command.

### Server Command Registry

Following the malum `@register` decorator pattern:

```python
COMMANDS: dict[str, Callable] = {}

def register(name: str):
    def decorator(func: Callable) -> Callable:
        COMMANDS[name] = func
        return func
    return decorator

# --- Connection lifecycle ---
@register("scan")
def cmd_scan(params: dict) -> dict: ...

@register("connect")
def cmd_connect(params: dict) -> dict: ...

@register("disconnect")
def cmd_disconnect(params: dict) -> dict: ...

# --- GATT operations ---
@register("get_gatt_map")
def cmd_get_gatt_map(params: dict) -> dict: ...

@register("read_characteristic")
def cmd_read_characteristic(params: dict) -> dict: ...

@register("write_characteristic")
def cmd_write_characteristic(params: dict) -> dict: ...

@register("write_no_response")
def cmd_write_no_response(params: dict) -> dict: ...

@register("subscribe")
def cmd_subscribe(params: dict) -> dict: ...

@register("unsubscribe")
def cmd_unsubscribe(params: dict) -> dict: ...

@register("probe_permissions")
def cmd_probe_permissions(params: dict) -> dict: ...

# --- Security testing ---
@register("pair")
def cmd_pair(params: dict) -> dict: ...

@register("unpair")
def cmd_unpair(params: dict) -> dict: ...

@register("test_encryption")
def cmd_test_encryption(params: dict) -> dict: ...

@register("fuzz_characteristic")
def cmd_fuzz_characteristic(params: dict) -> dict: ...

@register("replay_writes")
def cmd_replay_writes(params: dict) -> dict: ...

@register("test_auth_bypass")
def cmd_test_auth_bypass(params: dict) -> dict: ...

@register("get_connection_params")
def cmd_get_connection_params(params: dict) -> dict: ...

# --- Utility ---
@register("ping")
def cmd_ping(params: dict) -> dict: ...

@register("get_state")
def cmd_get_state(params: dict) -> dict: ...

@register("get_notification_buffer")
def cmd_get_notification_buffer(params: dict) -> dict: ...

@register("shutdown")
def cmd_shutdown(params: dict) -> dict: ...
```

### Environment Variables

```bash
PROTEUS_PYTHON=python3           # Python interpreter path
PROTEUS_ADAPTER=hci0             # BlueZ adapter
PROTEUS_TRANSPORT=usb            # usb or network (for remote testing)
PROTEUS_DEVICE_ID=               # Specific adapter ID for multi-adapter
PROTEUS_SNIFFER_HARDWARE=        # ubertooth|nrf52|sniffle (for sniffer server)
PROTEUS_ENGAGEMENT_DIR=          # Override engagement output directory
```

### Key Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| IPC Protocol | YAML over stdin/stdout | Ecosystem consistency with malum/draco |
| BLE Library | bleak (primary), bluepy (fallback) | bleak is async-native, best maintained |
| Server split | proteus-server + proteus-sniffer | Different hardware, avoid multiplexing |
| Offline scripts | Standalone TypeScript | No BLE connection needed, testable, runnable outside agents |
| Command pattern | `@register` decorator | Proven in malum/draco/headless-ghidra |
| Client pattern | Singleton + auto-restart | Proven in malum/draco |

---

## Next Steps

1. Implement `proteus-ble-server.py` with core connection lifecycle commands (`scan`, `connect`, `disconnect`, `get_gatt_map`, `read_characteristic`, `write_characteristic`)
2. Implement `lib/client.ts` following malum's singleton pattern
3. Build `ble-recon` agent (Phase 1) with wrappers for flows 1.1–1.5
4. Define `ble:proteus` skill definition following malum/draco SKILL.md pattern
5. Implement `ble-orchestrator` agent with operator interaction routing
