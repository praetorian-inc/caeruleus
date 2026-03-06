/**
 * analyze-advertisements.ts — Advertisement data analysis (Flow 1.5)
 *
 * Parses raw advertisement/scan response payloads, decodes manufacturer-specific
 * data, identifies information leakage (serial numbers, firmware versions, etc.).
 * Offline: reads device-inventory.json, no server needed.
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const analyzeAdvertisementsParams = z.object({
  device_inventory_path: z.string(),
  target_mac: z.string().optional(),
});
export type AnalyzeAdvertisementsInput = z.infer<typeof analyzeAdvertisementsParams>;

// Patterns that indicate information leakage in advertisement data
const LEAKAGE_PATTERNS = [
  { name: 'Serial Number', pattern: /(?:SN|S\/N|serial)[:\s_-]*([A-Z0-9]{6,})/i },
  { name: 'Firmware Version', pattern: /(?:FW|firmware|ver|version)[:\s_-]*(\d+\.\d+[\.\d]*)/i },
  { name: 'Hardware Version', pattern: /(?:HW|hardware)[:\s_-]*(\d+\.\d+[\.\d]*)/i },
  { name: 'MAC Address in Name', pattern: /([0-9A-F]{2}[:-]){2,5}[0-9A-F]{2}/i },
  { name: 'Numeric ID', pattern: /\b\d{8,}\b/ },
  { name: 'Model Number', pattern: /(?:model|MDL)[:\s_-]*([A-Z0-9]{3,})/i },
];

// Known manufacturer data decoders
function decodeManufacturerData(
  companyId: string,
  hexData: string,
): Record<string, unknown> {
  const decoded: Record<string, unknown> = { raw_hex: hexData, company_id: companyId };

  // Apple iBeacon / Continuity
  if (companyId === '0x004C' || companyId === '76') {
    if (hexData.startsWith('0215')) {
      decoded.type = 'iBeacon';
      decoded.uuid = hexData.substring(4, 36);
      decoded.major = parseInt(hexData.substring(36, 40), 16);
      decoded.minor = parseInt(hexData.substring(40, 44), 16);
      decoded.tx_power = parseInt(hexData.substring(44, 46), 16) - 256;
    } else {
      decoded.type = 'Apple Continuity';
      decoded.continuity_type = hexData.substring(0, 2);
    }
  }

  // Microsoft
  if (companyId === '0x0006' || companyId === '6') {
    decoded.type = 'Microsoft Beacon';
    decoded.scenario_type = hexData.substring(0, 2);
  }

  // Eddystone (Google)
  if (companyId === '0x00E0' || companyId === '224') {
    decoded.type = 'Eddystone';
    const frameType = hexData.substring(0, 2);
    if (frameType === '00') decoded.frame = 'UID';
    else if (frameType === '10') decoded.frame = 'URL';
    else if (frameType === '20') decoded.frame = 'TLM';
    else if (frameType === '40') decoded.frame = 'EID';
  }

  return decoded;
}

function tryDecodeHex(hex: string): string | null {
  try {
    const bytes = Buffer.from(hex, 'hex');
    const text = bytes.toString('utf-8');
    if ([...text].every((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127)) {
      return text;
    }
  } catch {
    // Not valid UTF-8
  }
  return null;
}

export const analyzeAdvertisements = {
  name: 'caeruleus.analyze_advertisements',
  description:
    'Parse and analyze BLE advertisement data from device inventory. Identifies information leakage, decodes manufacturer-specific data, and flags security concerns.',
  parameters: analyzeAdvertisementsParams,

  async execute(input: AnalyzeAdvertisementsInput): Promise<Record<string, unknown>> {
    const validated = analyzeAdvertisementsParams.parse(input);

    const inventoryRaw = await readFile(validated.device_inventory_path, 'utf-8');
    const inventory = JSON.parse(inventoryRaw);

    const devices = inventory.devices || [];
    const targetDevices = validated.target_mac
      ? devices.filter(
          (d: Record<string, unknown>) =>
            (d.mac_address as string).toUpperCase() ===
            validated.target_mac!.toUpperCase(),
        )
      : devices;

    if (targetDevices.length === 0) {
      return { error: 'No matching devices found', devices_count: devices.length };
    }

    const analyses = targetDevices.map((device: Record<string, unknown>) => {
      const leakageFindings: Array<Record<string, unknown>> = [];
      const decodedMfgData: Array<Record<string, unknown>> = [];
      const securityConcerns: string[] = [];

      const deviceName = device.device_name as string | null;
      const mfgData = (device.manufacturer_data || {}) as Record<string, string>;
      const serviceData = (device.service_data || {}) as Record<string, string>;

      // Check device name for leakage
      if (deviceName) {
        for (const lp of LEAKAGE_PATTERNS) {
          const match = deviceName.match(lp.pattern);
          if (match) {
            leakageFindings.push({
              source: 'device_name',
              type: lp.name,
              value: match[0],
              severity: 'medium',
              description: `Device name contains ${lp.name}: "${match[0]}"`,
            });
          }
        }
      }

      // Decode manufacturer data
      for (const [companyId, hexData] of Object.entries(mfgData)) {
        const decoded = decodeManufacturerData(companyId, hexData);
        decodedMfgData.push(decoded);

        // Check for leakage in decoded text
        const asText = tryDecodeHex(hexData);
        if (asText) {
          decoded.decoded_text = asText;
          for (const lp of LEAKAGE_PATTERNS) {
            const match = asText.match(lp.pattern);
            if (match) {
              leakageFindings.push({
                source: 'manufacturer_data',
                type: lp.name,
                value: match[0],
                company_id: companyId,
                severity: 'medium',
                description: `Manufacturer data contains ${lp.name}: "${match[0]}"`,
              });
            }
          }
        }

        // Large manufacturer data may indicate excessive information exposure
        if (hexData.length > 60) {
          securityConcerns.push(
            `Large manufacturer data payload (${hexData.length / 2} bytes) — may contain excessive device information`,
          );
        }
      }

      // Service data analysis
      const decodedServiceData: Array<Record<string, unknown>> = [];
      for (const [uuid, hexData] of Object.entries(serviceData)) {
        const entry: Record<string, unknown> = { uuid, raw_hex: hexData };
        const asText = tryDecodeHex(hexData);
        if (asText) {
          entry.decoded_text = asText;
        }
        decodedServiceData.push(entry);
      }

      // Connectable without authentication = security concern
      if (device.connectable) {
        securityConcerns.push(
          'Device is connectable — accessible to any BLE client in range',
        );
      }

      // Public MAC = trackable
      if (device.mac_type === 'public') {
        securityConcerns.push(
          'Public MAC address — device is permanently trackable',
        );
      }

      return {
        mac_address: device.mac_address,
        device_name: deviceName,
        leakage_findings: leakageFindings,
        leakage_count: leakageFindings.length,
        decoded_manufacturer_data: decodedMfgData,
        decoded_service_data: decodedServiceData,
        security_concerns: securityConcerns,
        service_uuids: device.service_uuids || [],
        rssi_dbm: device.rssi_dbm,
      };
    });

    const totalLeakage = analyses.reduce(
      (sum: number, a: Record<string, unknown>) =>
        sum + (a.leakage_count as number),
      0,
    );

    const result = {
      schema_version: '1.0',
      devices_analyzed: analyses.length,
      total_leakage_findings: totalLeakage,
      analyses,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  analyzeAdvertisements
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
