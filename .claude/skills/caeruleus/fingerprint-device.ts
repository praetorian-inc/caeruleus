/**
 * fingerprint-device.ts — Device fingerprinting (Flow 1.4)
 *
 * Correlates advertisement data, GATT profile structure, and manufacturer OUI
 * against known device databases to identify chipset, firmware, and known CVEs.
 * Offline: reads device-inventory.json and gatt-map.json, no server needed.
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const fingerprintDeviceParams = z.object({
  device_inventory_path: z.string(),
  gatt_map_path: z.string().optional(),
  target_mac: z.string().optional(),
});
export type FingerprintDeviceInput = z.infer<typeof fingerprintDeviceParams>;

// Known BLE chipset signatures based on manufacturer IDs and GATT patterns
const CHIPSET_SIGNATURES: Array<{
  company_id: string;
  company_name: string;
  chipset: string;
  known_issues: string[];
}> = [
  {
    company_id: '0x0059',
    company_name: 'Nordic Semiconductor',
    chipset: 'nRF5x',
    known_issues: ['CVE-2019-17519 (Invalid L2CAP fragment)', 'CVE-2020-15509 (SweynTooth)'],
  },
  {
    company_id: '0x000D',
    company_name: 'Texas Instruments',
    chipset: 'CC26xx',
    known_issues: ['CVE-2020-16630 (BLE stack overflow)'],
  },
  {
    company_id: '0x004C',
    company_name: 'Apple, Inc.',
    chipset: 'Apple BLE',
    known_issues: [],
  },
  {
    company_id: '0x0075',
    company_name: 'Samsung Electronics',
    chipset: 'Samsung BLE',
    known_issues: [],
  },
  {
    company_id: '0x000A',
    company_name: 'Qualcomm',
    chipset: 'QCC/CSR',
    known_issues: ['CVE-2020-0069 (Qualcomm BLE stack)'],
  },
  {
    company_id: '0x0002',
    company_name: 'Intel Corporation',
    chipset: 'Intel BLE',
    known_issues: ['CVE-2020-12321 (BleedingTooth)'],
  },
  {
    company_id: '0x000F',
    company_name: 'Broadcom Corporation',
    chipset: 'BCM',
    known_issues: ['CVE-2019-11516 (Broadcom BLE buffer overflow)'],
  },
  {
    company_id: '0x0131',
    company_name: 'Cypress Semiconductor',
    chipset: 'PSoC/CYW',
    known_issues: [],
  },
  {
    company_id: '0x02E5',
    company_name: 'Espressif',
    chipset: 'ESP32',
    known_issues: [],
  },
  {
    company_id: '0x0046',
    company_name: 'MediaTek',
    chipset: 'MT76xx',
    known_issues: [],
  },
  {
    company_id: '0x0157',
    company_name: 'Dialog Semiconductor',
    chipset: 'DA14xxx',
    known_issues: [],
  },
  {
    company_id: '0x0047',
    company_name: 'Silicon Laboratories',
    chipset: 'EFR32',
    known_issues: [],
  },
];

// Known DFU service UUIDs
const DFU_SERVICES: Record<string, string> = {
  '0000fe59': 'Nordic DFU (Secure)',
  '00001530': 'Nordic DFU (Legacy)',
  '0000ffd0': 'TI OAD',
  '0000ffc0': 'Microchip OTA',
  '1d14d6ee-fd63-4fa1-bfa4-8f47b42119f0': 'Silicon Labs OTA',
};

export const fingerprintDevice = {
  name: 'caeruleus.fingerprint_device',
  description:
    'Correlate device advertisement data and GATT profile against known chipset/firmware databases. Identifies chipset, manufacturer, and known CVEs.',
  parameters: fingerprintDeviceParams,

  async execute(input: FingerprintDeviceInput): Promise<Record<string, unknown>> {
    const validated = fingerprintDeviceParams.parse(input);

    const inventoryRaw = await readFile(validated.device_inventory_path, 'utf-8');
    const inventory = JSON.parse(inventoryRaw);

    let gattMap: Record<string, unknown> | null = null;
    if (validated.gatt_map_path) {
      const gattRaw = await readFile(validated.gatt_map_path, 'utf-8');
      gattMap = JSON.parse(gattRaw);
    }

    // Find target device
    const devices = inventory.devices || [];
    const target = validated.target_mac
      ? devices.find(
          (d: Record<string, unknown>) =>
            (d.mac_address as string).toUpperCase() ===
            validated.target_mac!.toUpperCase(),
        )
      : devices.find((d: Record<string, unknown>) => d.is_target) || devices[0];

    if (!target) {
      return { error: 'No target device found in inventory', devices_count: devices.length };
    }

    // Chipset identification
    const mfgData = (target.manufacturer_data || {}) as Record<string, string>;
    const companyIds = Object.keys(mfgData);
    const chipsetMatches = companyIds
      .map((id) => CHIPSET_SIGNATURES.find((s) => s.company_id === id))
      .filter(Boolean);

    // DFU detection from GATT map
    let dfuDetected: Record<string, unknown> | null = null;
    if (gattMap && (gattMap as any).services) {
      for (const svc of (gattMap as any).services) {
        const uuidLower = (svc.uuid as string).toLowerCase().replace(/-/g, '');
        for (const [dfuUuid, dfuName] of Object.entries(DFU_SERVICES)) {
          if (uuidLower.includes(dfuUuid)) {
            dfuDetected = { present: true, type: dfuName, service_uuid: svc.uuid };
            break;
          }
        }
        if (dfuDetected) break;
      }
    }

    // MAC type analysis
    const macType = target.mac_type || 'unknown';
    const macAnalysis =
      macType === 'random'
        ? 'Random MAC — device may be harder to track but indicates modern BLE stack'
        : 'Public MAC — device uses fixed IEEE OUI, trackable';

    // Aggregate known CVEs
    const knownCves = chipsetMatches.flatMap(
      (m) => (m as (typeof CHIPSET_SIGNATURES)[0]).known_issues,
    );

    const result = {
      schema_version: '1.0',
      target_mac: target.mac_address,
      device_name: target.device_name,
      chipset: chipsetMatches.length > 0
        ? {
            identified: true,
            company: (chipsetMatches[0] as (typeof CHIPSET_SIGNATURES)[0]).company_name,
            chipset_family: (chipsetMatches[0] as (typeof CHIPSET_SIGNATURES)[0]).chipset,
            company_id: companyIds[0],
          }
        : { identified: false, company_ids: companyIds },
      mac_analysis: { type: macType, note: macAnalysis },
      dfu_detected: dfuDetected || { present: false },
      known_cves: knownCves,
      known_cve_count: knownCves.length,
      service_uuids: target.service_uuids || [],
      rssi_dbm: target.rssi_dbm,
      advertisement_count: target.advertisement_count,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  fingerprintDevice
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
