/**
 * replay-writes.ts — Replay attack testing (Flow 3.5)
 *
 * Captures authenticated write sequences then replays after unpairing/re-pairing.
 * Tests whether device accepts stale commands (missing replay protection).
 * Online: requires caeruleus-server.py (Prepare-Execute-Capture pattern)
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const replayWritesParams = z.object({
  mac_address: BleMacAddressSchema,
  writes: z.array(
    z.object({
      uuid: z.string().min(4),
      value_hex: z.string().regex(/^[0-9a-fA-F]*$/),
    }),
  ),
  unpair_before_replay: z.boolean().default(true),
});
export type ReplayWritesInput = z.infer<typeof replayWritesParams>;

export const replayWrites = {
  name: 'caeruleus.replay_writes',
  description:
    'Replay previously captured BLE write sequences to test replay protection. Optionally unpairs before replay to test session invalidation.',
  parameters: replayWritesParams,

  async execute(
    input: ReplayWritesInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = replayWritesParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected
    await callFn('connect', { mac_address: validated.mac_address });

    // Optionally unpair to test session invalidation
    if (validated.unpair_before_replay) {
      try {
        await callFn('unpair', {});
      } catch {
        // May not be paired — continue
      }
    }

    const raw = (await callFn('replay_writes', {
      mac_address: validated.mac_address,
      writes: validated.writes,
    })) as Record<string, unknown>;

    const findings: Array<Record<string, unknown>> = [];
    const accepted = raw.accepted as number;

    if (accepted > 0) {
      findings.push({
        finding_id: 'F-atk-replay-001',
        type: 'missing_replay_protection',
        severity: 'high',
        description: `Device accepted ${accepted} of ${raw.total_replayed} replayed writes${validated.unpair_before_replay ? ' after unpairing' : ''}. No replay protection detected.`,
        accepted_writes: (raw.results as Array<Record<string, unknown>>)
          .filter((r) => r.accepted)
          .map((r) => ({ uuid: r.uuid, value_hex: r.value_hex })),
      });
    }

    const result = {
      total_replayed: raw.total_replayed,
      accepted,
      rejected: raw.rejected,
      replay_protection: raw.replay_protection,
      unpaired_before_replay: validated.unpair_before_replay,
      results: raw.results,
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
  replayWrites
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
