/**
 * analyze-connection-params.ts — Connection parameter analysis (Flow 2.6)
 *
 * Examines connection intervals, slave latency, supervision timeout, MTU.
 * Identifies configurations that weaken security or enable DoS.
 * Online: requires caeruleus-server.py
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const analyzeConnectionParamsParams = z.object({
  mac_address: BleMacAddressSchema,
});
export type AnalyzeConnectionParamsInput = z.infer<typeof analyzeConnectionParamsParams>;

export const analyzeConnectionParams = {
  name: 'caeruleus.analyze_connection_params',
  description:
    'Examine BLE connection parameters (intervals, latency, timeout, MTU) and identify security weaknesses.',
  parameters: analyzeConnectionParamsParams,

  async execute(
    input: AnalyzeConnectionParamsInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = analyzeConnectionParamsParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected
    await callFn('connect', { mac_address: validated.mac_address });

    const raw = (await callFn('get_connection_params', {})) as Record<string, unknown>;

    const findings: Array<Record<string, unknown>> = [];

    const connInterval = raw.connection_interval_ms as number | undefined;
    const slaveLatency = raw.slave_latency as number | undefined;
    const supervisionTimeout = raw.supervision_timeout_ms as number | undefined;
    const mtu = raw.mtu as number | undefined;

    // Check for weak connection parameters
    if (connInterval && connInterval > 200) {
      findings.push({
        type: 'slow_connection_interval',
        severity: 'informational',
        description: `Connection interval is ${connInterval}ms — slow interval may indicate energy-constrained device`,
      });
    }

    if (slaveLatency && slaveLatency > 10) {
      findings.push({
        type: 'high_slave_latency',
        severity: 'low',
        description: `Slave latency is ${slaveLatency} — high latency may indicate device is power-constrained`,
      });
    }

    if (supervisionTimeout && supervisionTimeout < 1000) {
      findings.push({
        type: 'short_supervision_timeout',
        severity: 'informational',
        description: `Supervision timeout is ${supervisionTimeout}ms — short timeout may cause spurious disconnects during fuzzing`,
      });
    }

    if (mtu && mtu < 50) {
      findings.push({
        type: 'small_mtu',
        severity: 'informational',
        description: `MTU is ${mtu} — small MTU limits write payload size for testing`,
      });
    }

    // Large MTU with no encryption = more data exposed per packet
    if (mtu && mtu > 200) {
      findings.push({
        type: 'large_mtu_exposure',
        severity: 'low',
        description: `MTU is ${mtu} — large MTU means more data per packet, higher exposure if unencrypted`,
      });
    }

    const result = {
      schema_version: '1.0',
      mac_address: validated.mac_address,
      connection_interval_ms: connInterval,
      slave_latency: slaveLatency,
      supervision_timeout_ms: supervisionTimeout,
      mtu,
      raw_params: raw,
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
  analyzeConnectionParams
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
