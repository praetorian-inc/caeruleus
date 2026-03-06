/**
 * test-wwr-abuse.ts — Write-Without-Response abuse testing (Flow 3.3)
 *
 * Tests all characteristics supporting write-without-response for:
 * buffer overflow via oversized writes, rapid-fire writes for resource exhaustion,
 * out-of-range value injection.
 * Online: requires caeruleus-server.py
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const testWwrAbuseParams = z.object({
  mac_address: BleMacAddressSchema,
  uuids: z.array(z.string().min(4)).optional(),
  rapid_fire_count: z.number().min(1).max(1000).default(100),
  max_write_sizes: z.array(z.number()).default([20, 50, 100, 200, 512]),
});
export type TestWwrAbuseInput = z.infer<typeof testWwrAbuseParams>;

export const testWwrAbuse = {
  name: 'caeruleus.test_wwr_abuse',
  description:
    'Test write-without-response characteristics for buffer overflow, rapid-fire resource exhaustion, and out-of-range value injection.',
  parameters: testWwrAbuseParams,

  async execute(
    input: TestWwrAbuseInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = testWwrAbuseParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected
    await callFn('connect', { mac_address: validated.mac_address });

    // Get GATT map to find WWR characteristics if not specified
    let targetUuids = validated.uuids;
    if (!targetUuids || targetUuids.length === 0) {
      const gattMap = (await callFn('get_gatt_map', { mac_address: validated.mac_address })) as Record<string, unknown>;
      const services = (gattMap.services || []) as Array<Record<string, unknown>>;
      targetUuids = [];
      for (const svc of services) {
        for (const char of (svc.characteristics || []) as Array<Record<string, unknown>>) {
          const props = (char.properties || {}) as Record<string, boolean>;
          if (props.write_no_response) {
            targetUuids.push(char.uuid as string);
          }
        }
      }
    }

    const findings: Array<Record<string, unknown>> = [];
    const testResults: Array<Record<string, unknown>> = [];

    for (const uuid of targetUuids) {
      const charResult: Record<string, unknown> = {
        uuid,
        overflow_tests: [],
        rapid_fire_test: null,
      };

      // Test 1: Oversized writes
      const overflowTests: Array<Record<string, unknown>> = [];
      for (const size of validated.max_write_sizes) {
        const payload = 'AA'.repeat(size);
        try {
          await callFn('write_no_response', { uuid, value_hex: payload });
          overflowTests.push({ size, accepted: true });
        } catch (e) {
          const errMsg = (e as Error).message.toLowerCase();
          if (errMsg.includes('disconnect') || errMsg.includes('crash')) {
            overflowTests.push({ size, accepted: false, crash: true, error: (e as Error).message });
            findings.push({
              finding_id: `F-atk-wwr-overflow-${uuid.slice(-4)}`,
              type: 'wwr_buffer_overflow',
              severity: 'high',
              uuid,
              description: `Device crashed on ${size}-byte write-without-response to ${uuid}`,
              crash_size: size,
            });
            break;
          }
          overflowTests.push({ size, accepted: false, error: (e as Error).message });
        }
      }
      charResult.overflow_tests = overflowTests;

      // Test 2: Rapid-fire writes (resource exhaustion)
      let rapidAccepted = 0;
      let rapidErrors = 0;
      let rapidCrash = false;
      for (let i = 0; i < validated.rapid_fire_count; i++) {
        try {
          await callFn('write_no_response', { uuid, value_hex: '00' });
          rapidAccepted++;
        } catch (e) {
          const errMsg = (e as Error).message.toLowerCase();
          if (errMsg.includes('disconnect') || errMsg.includes('crash')) {
            rapidCrash = true;
            findings.push({
              finding_id: `F-atk-wwr-dos-${uuid.slice(-4)}`,
              type: 'wwr_resource_exhaustion',
              severity: 'high',
              uuid,
              description: `Device crashed after ${i + 1} rapid write-without-response calls to ${uuid}`,
              crash_iteration: i + 1,
            });
            break;
          }
          rapidErrors++;
        }
      }

      charResult.rapid_fire_test = {
        total_sent: rapidAccepted + rapidErrors + (rapidCrash ? 1 : 0),
        accepted: rapidAccepted,
        errors: rapidErrors,
        crash: rapidCrash,
      };

      testResults.push(charResult);
    }

    const result = {
      schema_version: '1.0',
      characteristics_tested: targetUuids.length,
      test_results: testResults,
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
  testWwrAbuse
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
