/**
 * visualize-gatt.ts — GATT map visualization (Flow 4.1)
 *
 * Generates a text-based tree representation of the full GATT hierarchy
 * annotated with properties, permissions, and security findings.
 * Offline: reads gatt-map.json, no server needed.
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const visualizeGattParams = z.object({
  gatt_map_path: z.string(),
  findings_path: z.string().optional(),
  format: z.enum(['text', 'markdown']).default('text'),
});
export type VisualizeGattInput = z.infer<typeof visualizeGattParams>;

function propsToString(props: Record<string, boolean>): string {
  const flags: string[] = [];
  if (props.read) flags.push('R');
  if (props.write) flags.push('W');
  if (props.write_no_response) flags.push('WNR');
  if (props.notify) flags.push('N');
  if (props.indicate) flags.push('I');
  if (props.broadcast) flags.push('B');
  if (props.authenticated_signed_writes) flags.push('ASW');
  if (props.extended_properties) flags.push('EXT');
  return flags.join('|') || 'none';
}

function securityToString(security: Record<string, string>): string {
  const parts: string[] = [];
  if (security.read_requires !== 'none') parts.push(`read:${security.read_requires}`);
  if (security.write_requires !== 'none') parts.push(`write:${security.write_requires}`);
  return parts.length > 0 ? parts.join(', ') : 'open';
}

export const visualizeGatt = {
  name: 'caeruleus.visualize_gatt',
  description:
    'Generate a text or markdown tree visualization of the GATT hierarchy with properties and security annotations.',
  parameters: visualizeGattParams,

  async execute(input: VisualizeGattInput): Promise<Record<string, unknown>> {
    const validated = visualizeGattParams.parse(input);

    const gattRaw = await readFile(validated.gatt_map_path, 'utf-8');
    const gattMap = JSON.parse(gattRaw);

    // Load findings for annotation
    let findingsMap: Map<string, Array<Record<string, unknown>>> = new Map();
    if (validated.findings_path) {
      try {
        const findingsRaw = await readFile(validated.findings_path, 'utf-8');
        const findingsData = JSON.parse(findingsRaw);
        for (const f of (findingsData.findings || []) as Array<Record<string, unknown>>) {
          const uuid = (f.uuid || f.characteristic || '') as string;
          if (uuid) {
            if (!findingsMap.has(uuid)) findingsMap.set(uuid, []);
            findingsMap.get(uuid)!.push(f);
          }
        }
      } catch {
        // Findings file optional
      }
    }

    const lines: string[] = [];
    const md = validated.format === 'markdown';
    const services = (gattMap.services || []) as Array<Record<string, unknown>>;

    if (md) {
      lines.push(`# GATT Map: ${gattMap.device_mac || 'Unknown'}`);
      lines.push('');
      lines.push(`MTU: ${gattMap.mtu || 'N/A'} | Services: ${services.length}`);
      lines.push('');
    } else {
      lines.push(`GATT Map: ${gattMap.device_mac || 'Unknown'} (MTU: ${gattMap.mtu || 'N/A'})`);
      lines.push('='.repeat(60));
    }

    for (const svc of services) {
      const svcName = svc.name || 'Unknown Service';
      const svcType = svc.type === 'standard' ? '[STD]' : '[CUSTOM]';
      const chars = (svc.characteristics || []) as Array<Record<string, unknown>>;

      if (md) {
        lines.push(`## ${svcType} ${svcName}`);
        lines.push(`UUID: \`${svc.uuid}\` | Handles: ${svc.handle_start}–${svc.handle_end} | Chars: ${chars.length}`);
        lines.push('');
      } else {
        lines.push(`\n${svcType} ${svcName}`);
        lines.push(`  UUID: ${svc.uuid}`);
        lines.push(`  Handles: ${svc.handle_start} – ${svc.handle_end}`);
      }

      for (const char of chars) {
        const charName = char.name || 'Unknown';
        const props = (char.properties || {}) as Record<string, boolean>;
        const security = (char.security || {}) as Record<string, string>;
        const propStr = propsToString(props);
        const secStr = securityToString(security);
        const charUuid = char.uuid as string;

        const charFindings = findingsMap.get(charUuid) || [];
        const findingAnnotation = charFindings.length > 0
          ? ` ⚠ ${charFindings.length} finding(s)`
          : '';

        if (md) {
          lines.push(`### ${charName}${findingAnnotation}`);
          lines.push(`- UUID: \`${charUuid}\``);
          lines.push(`- Handle: ${char.handle} (value: ${char.value_handle})`);
          lines.push(`- Properties: \`${propStr}\``);
          lines.push(`- Security: ${secStr}`);

          if (char.value) {
            const val = char.value as Record<string, unknown>;
            lines.push(`- Value: \`${val.raw_hex}\`${val.decoded ? ` (${val.decoded})` : ''}`);
          }

          const descs = (char.descriptors || []) as Array<Record<string, unknown>>;
          if (descs.length > 0) {
            lines.push(`- Descriptors:`);
            for (const d of descs) {
              lines.push(`  - \`${d.uuid}\` ${d.name || ''}: ${d.value_hex || 'N/A'}`);
            }
          }

          for (const f of charFindings) {
            lines.push(`- **Finding [${f.severity}]**: ${f.description}`);
          }
          lines.push('');
        } else {
          lines.push(`  ├── ${charName} [${propStr}] (${secStr})${findingAnnotation}`);
          lines.push(`  │   UUID: ${charUuid}`);
          lines.push(`  │   Handle: ${char.handle} → ${char.value_handle}`);

          if (char.value) {
            const val = char.value as Record<string, unknown>;
            lines.push(`  │   Value: ${val.raw_hex}${val.decoded ? ` (${val.decoded})` : ''}`);
          }

          const descs = (char.descriptors || []) as Array<Record<string, unknown>>;
          for (const d of descs) {
            lines.push(`  │   └── ${d.uuid} ${d.name || ''}: ${d.value_hex || 'N/A'}`);
          }

          for (const f of charFindings) {
            lines.push(`  │   ⚠ [${f.severity}] ${f.description}`);
          }
        }
      }
    }

    const visualization = lines.join('\n');

    const result = {
      schema_version: '1.0',
      format: validated.format,
      device_mac: gattMap.device_mac,
      services_count: services.length,
      visualization,
      visualization_length: visualization.length,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  visualizeGatt
    .execute(input)
    .then((r) => console.log((r as Record<string, unknown>).visualization))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
