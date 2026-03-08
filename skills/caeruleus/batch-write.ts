/**
 * batch-write.ts — Write to multiple BLE characteristics in a single connection
 *
 * Writes a list of UUID+value pairs sequentially over one persistent connection.
 * Supports optional read-after-write to capture responses.
 * Online: requires caeruleus-server.py
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

const WriteEntrySchema = z.object({
  uuid: z.string().optional(),
  handle: z.number().optional(),
  value_hex: z.string().regex(/^[0-9a-fA-F]*$/, 'Value must be hex string').optional(),
  value_ascii: z.string().optional(),
  response: z.boolean().default(true),
  read_after_write: z.boolean().default(false),
}).refine(
  (d) => d.value_hex !== undefined || d.value_ascii !== undefined,
  { message: 'Either value_hex or value_ascii is required' },
);

export const batchWriteParams = z.object({
  mac_address: BleMacAddressSchema,
  writes: z.array(WriteEntrySchema).min(1),
  delay_ms: z.number().min(0).max(5000).default(0),
});
export type BatchWriteInput = z.infer<typeof batchWriteParams>;

interface WriteResult {
  uuid?: string;
  handle?: number;
  value_hex: string;
  success: boolean;
  read_back_hex?: string;
  read_back_decoded?: string | null;
  error?: string;
}

export const batchWrite = {
  name: 'caeruleus.batch_write',
  description:
    'Write to multiple BLE characteristics in one session. Supports UUID or handle targeting, optional read-after-write, and configurable inter-write delay.',
  parameters: batchWriteParams,

  async execute(
    input: BatchWriteInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = batchWriteParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    await callFn('connect', { mac_address: validated.mac_address });

    const results: WriteResult[] = [];
    for (const entry of validated.writes) {
      const entryHex = entry.value_hex
        ?? Buffer.from(entry.value_ascii!, 'utf-8').toString('hex');
      try {
        if (entry.handle) {
          await callFn('write_handle', {
            handle: entry.handle,
            value_hex: entryHex,
          });
        } else if (entry.uuid) {
          const cmd = entry.response ? 'write_characteristic' : 'write_no_response';
          await callFn(cmd, {
            uuid: entry.uuid,
            value_hex: entryHex,
          });
        } else {
          throw new Error('Either uuid or handle is required');
        }

        const writeResult: WriteResult = {
          uuid: entry.uuid,
          handle: entry.handle,
          value_hex: entryHex,
          success: true,
        };

        if (entry.read_after_write) {
          try {
            const readCmd = entry.handle ? 'read_handle' : 'read_characteristic';
            const readParams: Record<string, unknown> = entry.handle
              ? { handle: entry.handle }
              : { uuid: entry.uuid };
            const readResult = (await callFn(readCmd, readParams)) as Record<string, unknown>;
            writeResult.read_back_hex = (readResult.raw_hex as string) ?? '';
            writeResult.read_back_decoded = (readResult.decoded as string) ?? null;
          } catch (readErr) {
            writeResult.read_back_hex = '';
            writeResult.read_back_decoded = `read error: ${(readErr as Error).message}`;
          }
        }

        results.push(writeResult);
      } catch (e) {
        results.push({
          uuid: entry.uuid,
          handle: entry.handle,
          value_hex: entryHex,
          success: false,
          error: (e as Error).message,
        });
      }

      if (validated.delay_ms > 0) {
        await new Promise((r) => setTimeout(r, validated.delay_ms));
      }
    }

    const result = {
      mac_address: validated.mac_address,
      total_writes: validated.writes.length,
      successful: results.filter((r) => r.success).length,
      failed: results.filter((r) => !r.success).length,
      results,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  batchWrite
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
