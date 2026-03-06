/**
 * fuzz-characteristic.ts — Characteristic fuzzing execution (Flow 3.2)
 *
 * Executes fuzzing harnesses against writable characteristics, monitors for
 * crashes/hangs/unexpected responses, logs anomalies with triggering input.
 * Online: requires caeruleus-server.py (Prompt-and-Wait for crash recovery)
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const fuzzCharacteristicParams = z.object({
  mac_address: BleMacAddressSchema,
  uuid: z.string().min(4),
  strategy: z.enum(['random', 'boundary', 'type_aware', 'overflow']).default('type_aware'),
  iterations: z.number().min(1).max(10000).default(100),
  delay_ms: z.number().min(0).max(5000).default(50),
});
export type FuzzCharacteristicInput = z.infer<typeof fuzzCharacteristicParams>;

export const fuzzCharacteristic = {
  name: 'caeruleus.fuzz_characteristic',
  description:
    'Fuzz a BLE characteristic with type-aware, boundary, overflow, or random inputs. Monitors for crashes and anomalies.',
  parameters: fuzzCharacteristicParams,

  async execute(
    input: FuzzCharacteristicInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = fuzzCharacteristicParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected
    await callFn('connect', { mac_address: validated.mac_address });

    const raw = (await callFn('fuzz_characteristic', {
      mac_address: validated.mac_address,
      uuid: validated.uuid,
      strategy: validated.strategy,
      iterations: validated.iterations,
      delay_ms: validated.delay_ms,
    })) as Record<string, unknown>;

    const crashes = (raw.crashes as Array<Record<string, unknown>>) || [];
    const errors = (raw.errors as Array<Record<string, unknown>>) || [];

    const findings: Array<Record<string, unknown>> = [];

    if (crashes.length > 0) {
      findings.push({
        finding_id: `F-atk-fuzz-${validated.uuid.slice(-4)}`,
        type: 'device_crash',
        severity: 'high',
        description: `Device crashed ${crashes.length} time(s) during fuzzing of ${validated.uuid}`,
        crash_inputs: crashes.map((c) => c.input_hex),
        first_crash_iteration: crashes[0]?.iteration,
      });
    }

    if (errors.length > 10) {
      findings.push({
        type: 'excessive_errors',
        severity: 'medium',
        description: `${errors.length} errors during fuzzing — may indicate input validation issues`,
      });
    }

    const result = {
      uuid: validated.uuid,
      strategy: validated.strategy,
      iterations_planned: validated.iterations,
      iterations_completed: raw.iterations_completed,
      crashes_found: crashes.length,
      errors_found: errors.length,
      crashes,
      errors: errors.slice(0, 20), // Truncate for token efficiency
      findings,
      start_time: raw.start_time,
      end_time: raw.end_time,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  fuzzCharacteristic
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
