/**
 * test-pairing.ts — Pairing & bonding analysis (Flow 2.1)
 *
 * Tests pairing methods, enforcement, legacy fallback, IO capability mismatch.
 * Online: requires caeruleus-server.py (Prepare-Execute-Capture pattern)
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const testPairingParams = z.object({
  mac_address: BleMacAddressSchema,
  test_legacy_fallback: z.boolean().default(true),
  test_enforcement: z.boolean().default(true),
});
export type TestPairingInput = z.infer<typeof testPairingParams>;

export const testPairing = {
  name: 'caeruleus.test_pairing',
  description:
    'Analyze BLE pairing methods, test enforcement, and check for legacy fallback vulnerabilities.',
  parameters: testPairingParams,

  async execute(
    input: TestPairingInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = testPairingParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected
    await callFn('connect', { mac_address: validated.mac_address });

    const results: Record<string, unknown> = {
      mac_address: validated.mac_address,
      pairing_tests: [],
      findings: [],
    };

    // Test 1: Access characteristics without pairing
    const preTests: Array<Record<string, unknown>> = [];
    if (validated.test_enforcement) {
      const encResult = (await callFn('test_encryption', {})) as Record<string, unknown>;
      preTests.push({
        test: 'access_without_pairing',
        unencrypted_count: (encResult.unencrypted_characteristics as string[])?.length ?? 0,
        encrypted_count: (encResult.encrypted_characteristics as string[])?.length ?? 0,
        result: encResult,
      });

      if (((encResult.unencrypted_characteristics as string[])?.length ?? 0) > 0) {
        (results.findings as Array<Record<string, unknown>>).push({
          type: 'pairing_not_enforced',
          severity: 'high',
          description: 'Characteristics accessible without pairing',
          unencrypted: encResult.unencrypted_characteristics,
        });
      }
    }

    // Test 2: Attempt pairing
    let pairResult: Record<string, unknown> = {};
    try {
      pairResult = (await callFn('pair', {})) as Record<string, unknown>;
      (results.pairing_tests as Array<Record<string, unknown>>).push({
        test: 'pair_attempt',
        success: true,
        result: pairResult,
      });
    } catch (e) {
      (results.pairing_tests as Array<Record<string, unknown>>).push({
        test: 'pair_attempt',
        success: false,
        error: (e as Error).message,
      });
    }

    // Test 3: Access after pairing (compare)
    if (validated.test_enforcement) {
      const postEncResult = (await callFn('test_encryption', {})) as Record<string, unknown>;
      preTests.push({
        test: 'access_after_pairing',
        unencrypted_count: (postEncResult.unencrypted_characteristics as string[])?.length ?? 0,
        encrypted_count: (postEncResult.encrypted_characteristics as string[])?.length ?? 0,
        result: postEncResult,
      });
    }

    // Test 4: Unpair and test again (legacy fallback)
    if (validated.test_legacy_fallback) {
      try {
        await callFn('unpair', {});
        const postUnpairResult = (await callFn('test_encryption', {})) as Record<string, unknown>;
        const stillAccessible = (postUnpairResult.unencrypted_characteristics as string[])?.length ?? 0;

        (results.pairing_tests as Array<Record<string, unknown>>).push({
          test: 'legacy_fallback',
          chars_accessible_after_unpair: stillAccessible,
          result: postUnpairResult,
        });

        if (stillAccessible > 0) {
          (results.findings as Array<Record<string, unknown>>).push({
            type: 'legacy_fallback',
            severity: 'medium',
            description: 'Characteristics still accessible after unpairing — possible legacy fallback',
          });
        }
      } catch (e) {
        (results.pairing_tests as Array<Record<string, unknown>>).push({
          test: 'legacy_fallback',
          error: (e as Error).message,
        });
      }
    }

    results.pre_pair_tests = preTests;
    results.estimatedTokens = estimateTokens(results);
    return results;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  testPairing
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
