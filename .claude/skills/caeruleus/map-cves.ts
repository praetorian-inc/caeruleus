/**
 * map-cves.ts — CVE & known vulnerability mapping (Flow 4.3)
 *
 * Maps identified chipset/firmware to known CVEs. Distinguishes known
 * issues from novel findings.
 * Offline: reads device-fingerprint.json, no server needed.
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const mapCvesParams = z.object({
  fingerprint_path: z.string(),
  findings_path: z.string().optional(),
});
export type MapCvesInput = z.infer<typeof mapCvesParams>;

// Known BLE CVE database (curated subset)
const BLE_CVE_DATABASE: Array<{
  cve_id: string;
  chipset_families: string[];
  severity: string;
  cvss: number;
  description: string;
  affected_versions: string;
  remediation: string;
}> = [
  {
    cve_id: 'CVE-2019-17519',
    chipset_families: ['nRF5x'],
    severity: 'high',
    cvss: 8.8,
    description: 'Invalid L2CAP fragment handling in Nordic nRF5 SDK allows remote code execution',
    affected_versions: 'nRF5 SDK < 15.3.0',
    remediation: 'Update to nRF5 SDK 15.3.0 or later',
  },
  {
    cve_id: 'CVE-2020-15509',
    chipset_families: ['nRF5x'],
    severity: 'high',
    cvss: 8.1,
    description: 'SweynTooth: Truncated L2CAP causes buffer overflow in Nordic BLE stack',
    affected_versions: 'Multiple SDK versions',
    remediation: 'Apply Nordic security patches',
  },
  {
    cve_id: 'CVE-2020-16630',
    chipset_families: ['CC26xx'],
    severity: 'high',
    cvss: 7.5,
    description: 'BLE stack overflow in Texas Instruments CC26xx devices',
    affected_versions: 'CC26xx SDK < 4.40',
    remediation: 'Update TI BLE-Stack to 4.40 or later',
  },
  {
    cve_id: 'CVE-2020-12321',
    chipset_families: ['Intel BLE'],
    severity: 'critical',
    cvss: 9.8,
    description: 'BleedingTooth: Multiple Linux Bluetooth vulnerabilities (Intel)',
    affected_versions: 'Linux kernel < 5.10',
    remediation: 'Update Linux kernel to 5.10+',
  },
  {
    cve_id: 'CVE-2019-11516',
    chipset_families: ['BCM'],
    severity: 'high',
    cvss: 8.8,
    description: 'Broadcom BLE buffer overflow via malformed L2CAP packets',
    affected_versions: 'Multiple Broadcom chipsets',
    remediation: 'Apply vendor firmware update',
  },
  {
    cve_id: 'CVE-2020-0069',
    chipset_families: ['QCC/CSR'],
    severity: 'high',
    cvss: 7.8,
    description: 'Qualcomm BLE stack privilege escalation',
    affected_versions: 'Multiple Qualcomm chipsets',
    remediation: 'Apply Qualcomm security bulletin patches',
  },
  {
    cve_id: 'CVE-2020-10135',
    chipset_families: ['nRF5x', 'CC26xx', 'ESP32', 'BCM', 'QCC/CSR', 'Intel BLE'],
    severity: 'medium',
    cvss: 5.4,
    description: 'BIAS: Bluetooth Impersonation Attack — affects all BLE implementations',
    affected_versions: 'All BLE 4.0–5.2',
    remediation: 'Implement mutual authentication, enforce Secure Connections Only mode',
  },
  {
    cve_id: 'CVE-2020-26558',
    chipset_families: ['nRF5x', 'CC26xx', 'ESP32', 'BCM', 'QCC/CSR', 'Intel BLE'],
    severity: 'medium',
    cvss: 5.4,
    description: 'Passkey entry protocol vulnerability in BLE — MITM during Passkey pairing',
    affected_versions: 'BLE 2.1–5.2',
    remediation: 'Use Numeric Comparison or OOB pairing instead of Passkey Entry',
  },
];

export const mapCves = {
  name: 'caeruleus.map_cves',
  description:
    'Map identified chipset/firmware from device fingerprint to known BLE CVEs. Distinguishes known vulnerabilities from novel findings.',
  parameters: mapCvesParams,

  async execute(input: MapCvesInput): Promise<Record<string, unknown>> {
    const validated = mapCvesParams.parse(input);

    const fpRaw = await readFile(validated.fingerprint_path, 'utf-8');
    const fingerprint = JSON.parse(fpRaw);

    // Identify chipset family
    const chipset = fingerprint.chipset as Record<string, unknown> | undefined;
    const chipsetFamily = chipset?.chipset_family as string | undefined;

    // Match CVEs
    const matchedCves = chipsetFamily
      ? BLE_CVE_DATABASE.filter((cve) =>
          cve.chipset_families.some((f) => chipsetFamily.includes(f) || f.includes(chipsetFamily)),
        )
      : [];

    // Always include generic BLE CVEs
    const genericCves = BLE_CVE_DATABASE.filter((cve) =>
      cve.chipset_families.length > 3 && !matchedCves.includes(cve),
    );

    const allCves = [...matchedCves, ...genericCves];

    // Cross-reference with existing findings if available
    let novelFindings: Array<Record<string, unknown>> = [];
    let knownFindings: Array<Record<string, unknown>> = [];

    if (validated.findings_path) {
      try {
        const findingsRaw = await readFile(validated.findings_path, 'utf-8');
        const findingsData = JSON.parse(findingsRaw);
        const findings = (findingsData.findings || []) as Array<Record<string, unknown>>;

        for (const finding of findings) {
          const cveRefs = (finding.cve_references || []) as string[];
          const matchesCve = allCves.some(
            (cve) =>
              cveRefs.includes(cve.cve_id) ||
              (finding.description as string || '').toLowerCase().includes(cve.cve_id.toLowerCase()),
          );

          if (matchesCve) {
            knownFindings.push(finding);
          } else {
            novelFindings.push(finding);
          }
        }
      } catch {
        // Findings file optional
      }
    }

    const result = {
      schema_version: '1.0',
      device_mac: fingerprint.target_mac,
      chipset_family: chipsetFamily || 'unknown',
      chipset_identified: chipset?.identified ?? false,
      matched_cves: allCves.map((cve) => ({
        cve_id: cve.cve_id,
        severity: cve.severity,
        cvss: cve.cvss,
        description: cve.description,
        affected_versions: cve.affected_versions,
        remediation: cve.remediation,
        chipset_specific: matchedCves.includes(cve),
      })),
      matched_cve_count: allCves.length,
      chipset_specific_cves: matchedCves.length,
      generic_ble_cves: genericCves.length,
      novel_findings: novelFindings,
      novel_findings_count: novelFindings.length,
      known_findings: knownFindings,
      known_findings_count: knownFindings.length,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  mapCves
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
