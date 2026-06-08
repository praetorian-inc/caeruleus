/**
 * raw-att.ts — Execute raw ATT operations via L2CAP socket
 *
 * Supports exchange_mtu, read, write, and listen operations that bypass Bleak.
 * Essential for MTU negotiation, handle-level reads, and raw ATT interactions
 * that Bleak doesn't expose.
 * Online: requires caeruleus-server.py on Linux/BlueZ.
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleHandleSchema, BleMacAddressSchema, estimateTokens } from './lib/types.js';

const AttOperationSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('exchange_mtu'),
    mtu: z.number().min(23).max(517),
  }),
  z.object({
    type: z.literal('read'),
    handle: BleHandleSchema.pipe(z.number().min(1)),
  }),
  z.object({
    type: z.literal('write'),
    handle: BleHandleSchema.pipe(z.number().min(1)),
    value_hex: z.string().regex(/^[0-9a-fA-F]*$/, 'Value must be hex string'),
  }),
  z.object({
    type: z.literal('listen'),
    duration: z.number().min(1).max(3600).default(10),
  }),
]);

export const rawAttParams = z.object({
  mac_address: BleMacAddressSchema,
  operations: z.array(AttOperationSchema).min(1),
});
export type RawAttInput = z.infer<typeof rawAttParams>;

export const rawAtt = {
  name: 'caeruleus.raw_att',
  description:
    'Execute raw ATT operations via L2CAP socket. Supports exchange_mtu, read, write, and listen. '
    + 'Bypasses Bleak — useful for MTU negotiation, handle-level reads, and raw ATT interactions.',
  parameters: rawAttParams,

  async execute(
    input: RawAttInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = rawAttParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected so the server has an active Bleak connection to resolve handles
    await callFn('connect', { mac_address: validated.mac_address });

    // Compute timeout: base 30s + any listen durations
    const listenDuration = validated.operations
      .filter((op): op is { type: 'listen'; duration: number } => op.type === 'listen')
      .reduce((sum, op) => sum + op.duration, 0);
    const timeoutMs = (30 + listenDuration + validated.operations.length * 5) * 1000;

    const result = (await callFn('raw_att', {
      mac_address: validated.mac_address,
      operations: validated.operations,
      timeout_ms: timeoutMs,
    })) as Record<string, unknown>;

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
  rawAtt
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
