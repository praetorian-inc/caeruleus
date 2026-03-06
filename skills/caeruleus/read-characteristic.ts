/**
 * read-characteristic.ts — Read BLE characteristic value
 *
 * Standalone wrapper for reading a single characteristic.
 * Online: requires caeruleus-server.py
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const readCharacteristicParams = z.object({
  mac_address: BleMacAddressSchema,
  uuid: z.string().min(4),
  handle: z.string().optional(),
});
export type ReadCharacteristicInput = z.infer<typeof readCharacteristicParams>;

export const readCharacteristic = {
  name: 'caeruleus.read_characteristic',
  description: 'Read the value of a BLE characteristic by UUID or handle.',
  parameters: readCharacteristicParams,

  async execute(
    input: ReadCharacteristicInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = readCharacteristicParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected
    await callFn('connect', { mac_address: validated.mac_address });

    const raw = (await callFn('read_characteristic', {
      uuid: validated.uuid,
      handle: validated.handle,
    })) as Record<string, unknown>;

    const result = {
      uuid: validated.uuid,
      handle: validated.handle,
      value_hex: raw.raw_hex as string ?? raw.value_hex as string,
      value_decoded: raw.decoded as string ?? raw.value_decoded as string,
      length: raw.length as number,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  readCharacteristic
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
