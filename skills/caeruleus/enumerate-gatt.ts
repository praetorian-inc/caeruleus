/**
 * enumerate-gatt.ts — GATT service & characteristic enumeration (Flow 1.2)
 *
 * Connects to target device, walks full GATT table, produces structured GATT map.
 * Online: requires caeruleus-server.py
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleConnectParamsSchema, BleGattMapSchema, BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const enumerateGattParams = z.object({
  mac_address: BleMacAddressSchema,
  mac_type: z.enum(['public', 'random']).default('public'),
  adapter: z.string().default('hci0'),
  timeout: z.number().min(1).max(60).default(15),
  force_refresh: z.boolean().default(false),
});
export type EnumerateGattInput = z.infer<typeof enumerateGattParams>;

export const enumerateGatt = {
  name: 'caeruleus.enumerate_gatt',
  description:
    'Connect to a BLE device and enumerate all GATT services, characteristics, and descriptors. Returns structured GATT map.',
  parameters: enumerateGattParams,

  async execute(
    input: EnumerateGattInput,
    client?: IBleClient,
  ): Promise<z.infer<typeof BleGattMapSchema> & { estimatedTokens: number }> {
    const validated = enumerateGattParams.parse(input);

    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Connect first
    await callFn('connect', {
      mac_address: validated.mac_address,
      mac_type: validated.mac_type,
      adapter: validated.adapter,
      timeout: validated.timeout,
    });

    // Get GATT map
    const raw = (await callFn('get_gatt_map', {
      force_refresh: validated.force_refresh,
    })) as Record<string, unknown>;

    const gattMap = BleGattMapSchema.parse(raw);

    return {
      ...gattMap,
      estimatedTokens: estimateTokens(gattMap),
    };
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  enumerateGatt
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(
        JSON.stringify({ error: err.message, code: err.code }, null, 2),
      );
      process.exit(1);
    });
}
