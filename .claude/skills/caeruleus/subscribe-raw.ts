/**
 * subscribe-raw.ts — Raw L2CAP ATT notification/indication capture
 *
 * Calls subscribe_raw directly, bypassing Bleak's start_notify fallback chain.
 * Essential for CCCD-less devices where the normal subscribe path times out.
 * Online: requires caeruleus-server.py on Linux/BlueZ.
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleHandleSchema, BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const subscribeRawParams = z.object({
  mac_address: BleMacAddressSchema,
  uuid: z.string().optional(),
  handle: BleHandleSchema.optional(),
  duration: z.number().min(1).max(3600).default(10),
  write_value_hex: z.string().optional(),
  enable_notifications: z.boolean().optional(),
  enable_indications: z.boolean().optional(),
});
export type SubscribeRawInput = z.infer<typeof subscribeRawParams>;

export const subscribeRaw = {
  name: 'caeruleus.subscribe_raw',
  description:
    'Subscribe to BLE notifications/indications via raw L2CAP ATT socket. Bypasses Bleak — works on CCCD-less devices.',
  parameters: subscribeRawParams,

  async execute(
    input: SubscribeRawInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = subscribeRawParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected so the server can resolve UUID → handle
    await callFn('connect', { mac_address: validated.mac_address });

    const rawParams: Record<string, unknown> = {
      mac_address: validated.mac_address,
      duration: validated.duration,
      timeout_ms: (validated.duration + 30) * 1000,
    };
    if (validated.uuid) rawParams.uuid = validated.uuid;
    if (validated.handle !== undefined) rawParams.write_handle = validated.handle;

    // Resolve write_value_hex: explicit value takes priority, then convenience flags
    if (validated.write_value_hex) {
      rawParams.write_value_hex = validated.write_value_hex;
    } else if (validated.enable_indications) {
      rawParams.write_value_hex = '0200';
    } else if (validated.enable_notifications) {
      rawParams.write_value_hex = '0100';
    }

    const result = (await callFn('subscribe_raw', rawParams)) as Record<string, unknown>;

    const output = {
      ...result,
      estimatedTokens: 0,
    };
    output.estimatedTokens = estimateTokens(output);
    return output;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  subscribeRaw
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
