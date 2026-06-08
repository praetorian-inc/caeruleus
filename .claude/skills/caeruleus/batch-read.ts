/**
 * batch-read.ts — Read multiple BLE characteristics in a single connection
 *
 * Reads a list of UUIDs (or all readable characteristics from a GATT map)
 * sequentially over one persistent connection. Useful for bulk data extraction.
 * Online: requires caeruleus-server.py
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

// Accept reads as plain UUID strings OR objects with a uuid field (mirrors batch-write's object style)
const ReadEntrySchema = z.union([
  z.string(),
  z.object({ uuid: z.string() }),
]);

export const batchReadParams = z.object({
  mac_address: BleMacAddressSchema,
  uuids: z.array(z.string()).optional(),
  reads: z.array(ReadEntrySchema).optional(),
  gatt_map_path: z.string().optional(),
  handles: z.array(z.number()).optional(),
});
export type BatchReadInput = z.infer<typeof batchReadParams>;

interface ReadResult {
  uuid?: string;
  handle?: number;
  value_hex: string;
  value_decoded: string | null;
  length: number;
  error?: string;
}

export const batchRead = {
  name: 'caeruleus.batch_read',
  description:
    'Read multiple BLE characteristics in one session. Accepts UUIDs, handles, or a GATT map path to auto-discover readable characteristics.',
  parameters: batchReadParams,

  async execute(
    input: BatchReadInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = batchReadParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    await callFn('connect', { mac_address: validated.mac_address });

    const targets: Array<{ uuid?: string; handle?: number }> = [];

    // Accept both `uuids` and `reads` (alias for symmetry with batch-write's `writes`)
    // `reads` entries can be plain UUID strings or {uuid: "..."} objects
    const normalizedReads = (validated.reads ?? []).map((entry) =>
      typeof entry === 'string' ? entry : entry.uuid,
    );
    const allUuids = [...(validated.uuids ?? []), ...normalizedReads];
    for (const uuid of allUuids) {
      targets.push({ uuid });
    }

    if (validated.handles) {
      for (const handle of validated.handles) {
        targets.push({ handle });
      }
    }

    if (targets.length === 0 && validated.gatt_map_path) {
      const gattRaw = await readFile(validated.gatt_map_path, 'utf-8');
      const gattMap = JSON.parse(gattRaw);
      for (const svc of gattMap.services || []) {
        for (const char of svc.characteristics || []) {
          if (char.properties?.read) {
            targets.push({ uuid: char.uuid });
          }
        }
      }
    }

    if (targets.length === 0) {
      return {
        error: 'No targets specified',
        suggestion: 'Provide uuids array, handles array, or gatt_map_path',
      };
    }

    const results: ReadResult[] = [];
    for (const target of targets) {
      try {
        const cmd = target.handle ? 'read_handle' : 'read_characteristic';
        const params: Record<string, unknown> = target.handle
          ? { handle: target.handle }
          : { uuid: target.uuid };
        const raw = (await callFn(cmd, params)) as Record<string, unknown>;
        results.push({
          uuid: target.uuid ?? (raw.uuid as string),
          handle: target.handle,
          value_hex: (raw.raw_hex as string) ?? '',
          value_decoded: (raw.decoded as string) ?? null,
          length: (raw.length as number) ?? 0,
        });
      } catch (e) {
        results.push({
          uuid: target.uuid,
          handle: target.handle,
          value_hex: '',
          value_decoded: null,
          length: 0,
          error: (e as Error).message,
        });
      }
    }

    const result = {
      mac_address: validated.mac_address,
      total_targets: targets.length,
      successful: results.filter((r) => !r.error).length,
      failed: results.filter((r) => r.error).length,
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
  batchRead
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
