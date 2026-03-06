/**
 * write-characteristic.ts — Write BLE characteristic value
 *
 * Standalone wrapper for writing to a single characteristic.
 * Online: requires caeruleus-server.py
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const writeCharacteristicParams = z.object({
  mac_address: BleMacAddressSchema,
  uuid: z.string().min(4),
  handle: z.string().optional(),
  value_hex: z.string().regex(/^[0-9a-fA-F]*$/, 'Value must be hex string'),
  response: z.boolean().default(true),
});
export type WriteCharacteristicInput = z.infer<typeof writeCharacteristicParams>;

export const writeCharacteristic = {
  name: 'caeruleus.write_characteristic',
  description: 'Write a value to a BLE characteristic by UUID or handle.',
  parameters: writeCharacteristicParams,

  async execute(
    input: WriteCharacteristicInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = writeCharacteristicParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected
    await callFn('connect', { mac_address: validated.mac_address });

    const command = validated.response ? 'write_characteristic' : 'write_no_response';
    const raw = (await callFn(command, {
      uuid: validated.uuid,
      handle: validated.handle,
      value_hex: validated.value_hex,
    })) as Record<string, unknown>;

    const result = {
      uuid: validated.uuid,
      handle: validated.handle,
      value_hex: validated.value_hex,
      response_mode: validated.response,
      success: raw.success ?? true,
      raw_response: raw,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  writeCharacteristic
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
