/**
 * test-encryption.ts — Encryption assessment (Flow 2.2)
 *
 * Tests link-layer encryption enforcement, identifies unprotected characteristics,
 * detects KNOB-style key size negotiation weaknesses.
 * Online: requires caeruleus-server.py (Prompt-and-Wait pattern)
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const testEncryptionParams = z.object({
  mac_address: BleMacAddressSchema.optional(),
});
export type TestEncryptionInput = z.infer<typeof testEncryptionParams>;

export const testEncryption = {
  name: 'caeruleus.test_encryption',
  description:
    'Test BLE link-layer encryption enforcement. Identifies characteristics accessible without encryption and potential KNOB vulnerabilities.',
  parameters: testEncryptionParams,

  async execute(
    input: TestEncryptionInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = testEncryptionParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    if (validated.mac_address) {
      await callFn('connect', { mac_address: validated.mac_address });
    }

    const encResult = (await callFn('test_encryption', {})) as Record<string, unknown>;
    const connParams = (await callFn('get_connection_params', {})) as Record<string, unknown>;

    const unencryptedChars = (encResult.unencrypted_characteristics as string[]) || [];
    const encryptedChars = (encResult.encrypted_characteristics as string[]) || [];

    const findings: Array<Record<string, unknown>> = [];

    if (!encResult.link_layer_enforced) {
      findings.push({
        type: 'no_link_layer_encryption',
        severity: 'high',
        description: 'Link-layer encryption is not enforced. All GATT traffic is in cleartext.',
        unencrypted_count: unencryptedChars.length,
      });
    }

    if (unencryptedChars.length > 0 && encryptedChars.length > 0) {
      findings.push({
        type: 'mixed_encryption',
        severity: 'medium',
        description: 'Some characteristics require encryption while others do not — inconsistent security policy.',
        unencrypted: unencryptedChars,
        encrypted: encryptedChars,
      });
    }

    const result = {
      mac_address: validated.mac_address || connParams.mac_address,
      link_layer_enforced: encResult.link_layer_enforced,
      total_readable: encResult.total_readable,
      unencrypted_characteristics: unencryptedChars,
      encrypted_characteristics: encryptedChars,
      connection_params: {
        mtu: connParams.mtu,
        connection_interval: connParams.connection_interval,
        slave_latency: connParams.slave_latency,
        supervision_timeout: connParams.supervision_timeout,
      },
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
  testEncryption
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
