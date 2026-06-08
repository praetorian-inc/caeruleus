/**
 * probe-characteristics.ts — Characteristic permission probing (Flow 1.3)
 *
 * Tests actual vs. advertised permissions for each characteristic.
 * Identifies unauthenticated read/write access and permission mismatches.
 * Online: requires caeruleus-server.py (must be connected first)
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const probeCharacteristicsParams = z.object({
  mac_address: BleMacAddressSchema,
  timeout_per_char: z.number().min(0.5).max(10).default(2),
});
export type ProbeCharacteristicsInput = z.infer<typeof probeCharacteristicsParams>;

const ProbeResultSchema = z.object({
  uuid: z.string(),
  handle: z.string(),
  advertisedProperties: z.record(z.boolean()),
  actualRead: z.string().nullable(),
  actualWrite: z.string().nullable(),
  readError: z.string().nullable(),
  writeError: z.string().nullable(),
  permissionMismatch: z.boolean(),
});

const ProbeOutputSchema = z.object({
  totalCharacteristics: z.number(),
  permissionMismatches: z.number(),
  results: z.array(ProbeResultSchema),
  estimatedTokens: z.number(),
});
export type ProbeCharacteristicsOutput = z.infer<typeof ProbeOutputSchema>;

interface RawProbeResult {
  uuid: string;
  handle: string;
  advertised_properties: Record<string, boolean>;
  actual_read: string | null;
  actual_write: string | null;
  read_error: string | null;
  write_error: string | null;
  permission_mismatch: boolean;
}

interface RawProbeResponse {
  total_characteristics: number;
  permission_mismatches: number;
  results: RawProbeResult[];
}

export const probeCharacteristics = {
  name: 'caeruleus.probe_characteristics',
  description:
    'Test actual read/write permissions for all characteristics on a connected device. Identifies permission mismatches and unauthenticated access.',
  parameters: probeCharacteristicsParams,

  async execute(
    input: ProbeCharacteristicsInput,
    client?: IBleClient,
  ): Promise<ProbeCharacteristicsOutput> {
    const validated = probeCharacteristicsParams.parse(input);

    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    const raw = (await callFn('probe_permissions', {
      mac_address: validated.mac_address,
      timeout_per_char: validated.timeout_per_char,
    })) as RawProbeResponse;

    const results = raw.results.map((r) => ({
      uuid: r.uuid,
      handle: r.handle,
      advertisedProperties: r.advertised_properties,
      actualRead: r.actual_read,
      actualWrite: r.actual_write,
      readError: r.read_error,
      writeError: r.write_error,
      permissionMismatch: r.permission_mismatch,
    }));

    const output: ProbeCharacteristicsOutput = {
      totalCharacteristics: raw.total_characteristics,
      permissionMismatches: raw.permission_mismatches,
      results,
      estimatedTokens: 0,
    };

    output.estimatedTokens = estimateTokens(output);
    return ProbeOutputSchema.parse(output);
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  probeCharacteristics
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
