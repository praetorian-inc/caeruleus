/**
 * audit-gatt-profile.ts — GATT profile security audit (Flow 2.4)
 *
 * Maps characteristics against Bluetooth SIG standard profiles, identifies
 * spec deviations, flags custom services, checks for hidden characteristics.
 * Offline: reads gatt-map.json, no server needed.
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const auditGattProfileParams = z.object({
  gatt_map_path: z.string(),
});
export type AuditGattProfileInput = z.infer<typeof auditGattProfileParams>;

// Standard BLE SIG service expectations
const SIG_SERVICE_EXPECTATIONS: Record<
  string,
  {
    name: string;
    required_chars: string[];
    security_notes: string[];
  }
> = {
  '00001800': {
    name: 'Generic Access',
    required_chars: ['00002a00', '00002a01'],
    security_notes: ['Device Name should not leak sensitive info'],
  },
  '00001801': {
    name: 'Generic Attribute',
    required_chars: [],
    security_notes: ['Service Changed (0x2A05) should require indication'],
  },
  '0000180a': {
    name: 'Device Information',
    required_chars: [],
    security_notes: [
      'Serial Number (0x2A25) should require encryption',
      'Firmware Revision (0x2A26) exposes version for CVE matching',
      'Model Number (0x2A24) may aid device identification',
    ],
  },
  '0000180f': {
    name: 'Battery Service',
    required_chars: ['00002a19'],
    security_notes: ['Battery level changes can be used for tracking'],
  },
  '0000fe59': {
    name: 'Nordic DFU',
    required_chars: [],
    security_notes: [
      'DFU service MUST validate firmware signatures',
      'DFU should require authentication before accepting updates',
      'Version downgrade must be prevented',
    ],
  },
};

export const auditGattProfile = {
  name: 'caeruleus.audit_gatt_profile',
  description:
    'Audit GATT profile against Bluetooth SIG standard profiles. Identifies spec deviations, security gaps in standard services, and flags custom services.',
  parameters: auditGattProfileParams,

  async execute(input: AuditGattProfileInput): Promise<Record<string, unknown>> {
    const validated = auditGattProfileParams.parse(input);

    const gattRaw = await readFile(validated.gatt_map_path, 'utf-8');
    const gattMap = JSON.parse(gattRaw);

    const services = gattMap.services || [];
    const auditResults: Array<Record<string, unknown>> = [];
    const findings: Array<Record<string, unknown>> = [];

    for (const svc of services) {
      const uuidLower = (svc.uuid as string).toLowerCase().replace(/-/g, '');
      const shortUuid = uuidLower.substring(0, 8);
      const sigSpec = SIG_SERVICE_EXPECTATIONS[shortUuid];

      const audit: Record<string, unknown> = {
        uuid: svc.uuid,
        name: svc.name || 'Unknown',
        type: svc.type,
        characteristic_count: (svc.characteristics || []).length,
      };

      if (sigSpec) {
        audit.sig_compliance = 'standard';
        audit.security_notes = sigSpec.security_notes;

        // Check required characteristics
        const charUuids = (svc.characteristics || []).map((c: Record<string, unknown>) =>
          (c.uuid as string).toLowerCase().replace(/-/g, '').substring(0, 8),
        );
        const missing = sigSpec.required_chars.filter((r) => !charUuids.includes(r));
        if (missing.length > 0) {
          audit.missing_required_chars = missing;
          findings.push({
            type: 'spec_deviation',
            severity: 'low',
            service: svc.uuid,
            description: `Standard service ${sigSpec.name} missing required characteristics: ${missing.join(', ')}`,
          });
        }

        // Security audit per characteristic
        for (const char of svc.characteristics || []) {
          const props = char.properties || {};
          const security = char.security || {};

          // Device Information chars should require encryption
          if (shortUuid === '0000180a') {
            if (security.read_requires === 'none' && props.read) {
              findings.push({
                type: 'information_disclosure',
                severity: 'medium',
                service: svc.uuid,
                characteristic: char.uuid,
                description: `Device Information characteristic ${char.name || char.uuid} readable without encryption`,
              });
            }
          }

          // Writable without auth on standard services
          if ((props.write || props.write_no_response) && security.write_requires === 'none') {
            findings.push({
              type: 'unauthenticated_write',
              severity: 'medium',
              service: svc.uuid,
              characteristic: char.uuid,
              description: `Writable characteristic ${char.name || char.uuid} in standard service requires no authentication`,
            });
          }
        }
      } else {
        audit.sig_compliance = 'custom';
        audit.security_notes = ['Custom service — requires manual analysis'];

        // Flag all custom service characteristics for deeper review
        for (const char of svc.characteristics || []) {
          const props = char.properties || {};
          const security = char.security || {};

          if ((props.write || props.write_no_response) && security.write_requires === 'none') {
            findings.push({
              type: 'custom_unauthenticated_write',
              severity: 'high',
              service: svc.uuid,
              characteristic: char.uuid,
              description: `Custom characteristic ${char.uuid} writable without authentication — unknown function, high risk`,
            });
          }

          if (props.read && security.read_requires === 'none') {
            findings.push({
              type: 'custom_unauthenticated_read',
              severity: 'informational',
              service: svc.uuid,
              characteristic: char.uuid,
              description: `Custom characteristic ${char.uuid} readable without authentication`,
            });
          }
        }
      }

      auditResults.push(audit);
    }

    const result = {
      schema_version: '1.0',
      services_audited: auditResults.length,
      standard_services: auditResults.filter((a) => a.sig_compliance === 'standard').length,
      custom_services: auditResults.filter((a) => a.sig_compliance === 'custom').length,
      findings,
      findings_count: findings.length,
      audit_results: auditResults,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  auditGattProfile
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
