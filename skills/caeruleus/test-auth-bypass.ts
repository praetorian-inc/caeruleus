/**
 * test-auth-bypass.ts — Authentication bypass testing (Flow 3.6)
 *
 * Tests accessing protected characteristics without pairing, with legacy pairing,
 * and with manipulated IO capabilities.
 * Online: requires caeruleus-server.py (Prompt-and-Wait pattern)
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const testAuthBypassParams = z.object({
  mac_address: BleMacAddressSchema,
  security_posture_path: z.string().optional(),
  target_uuids: z.array(z.string()).optional(),
});
export type TestAuthBypassInput = z.infer<typeof testAuthBypassParams>;

export const testAuthBypass = {
  name: 'caeruleus.test_auth_bypass',
  description:
    'Test authentication bypass by accessing protected characteristics without proper pairing or encryption.',
  parameters: testAuthBypassParams,

  async execute(
    input: TestAuthBypassInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = testAuthBypassParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected
    await callFn('connect', { mac_address: validated.mac_address });

    // Get target UUIDs from security posture or direct input
    let targetUuids = validated.target_uuids || [];

    if (targetUuids.length === 0 && validated.security_posture_path) {
      const postureRaw = await readFile(validated.security_posture_path, 'utf-8');
      const posture = JSON.parse(postureRaw);
      targetUuids = (posture.attack_surface_priority || []).map(
        (a: Record<string, unknown>) => a.characteristic_uuid as string,
      );
    }

    if (targetUuids.length === 0) {
      return {
        error: 'No target UUIDs specified',
        suggestion: 'Provide target_uuids array or security_posture_path',
      };
    }

    const raw = (await callFn('test_auth_bypass', {
      mac_address: validated.mac_address,
      target_uuids: targetUuids,
    })) as Record<string, unknown>;

    const results = (raw.results as Array<Record<string, unknown>>) || [];
    const findings: Array<Record<string, unknown>> = [];

    for (const r of results) {
      const readBypass = r.read_without_auth as Record<string, unknown> | null;
      const writeBypass = r.write_without_auth as Record<string, unknown> | null;

      if (readBypass?.success) {
        findings.push({
          finding_id: `F-atk-authbypass-read-${(r.uuid as string).slice(-4)}`,
          type: 'auth_bypass_read',
          severity: 'high',
          uuid: r.uuid,
          description: `Characteristic ${r.uuid} readable without authentication`,
          data_hex: readBypass.data_hex,
        });
      }

      if (writeBypass?.success) {
        findings.push({
          finding_id: `F-atk-authbypass-write-${(r.uuid as string).slice(-4)}`,
          type: 'auth_bypass_write',
          severity: 'critical',
          uuid: r.uuid,
          description: `Characteristic ${r.uuid} writable without authentication`,
        });
      }
    }

    const result = {
      total_tested: raw.total_tested,
      bypassed_count: raw.bypassed_count,
      results,
      findings,
      findings_count: findings.length,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  testAuthBypass
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
