/**
 * scan-devices.ts — BLE device discovery (Flow 1.1)
 *
 * Runs passive/active scanning, collects advertisement data, produces device inventory.
 * Online: requires caeruleus-server.py
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleScanParamsSchema, estimateTokens } from './lib/types.js';

export const scanDevicesParams = z.object({
  duration: z.number().min(1).max(300).default(10),
  adapter: z.string().default('hci0'),
  active: z.boolean().default(false),
  target_mac: z.string().optional(),
});
export type ScanDevicesInput = z.infer<typeof scanDevicesParams>;

const ScanDevicesOutputSchema = z.object({
  scanDurationSeconds: z.number(),
  adapter: z.string(),
  deviceCount: z.number(),
  devices: z.array(z.record(z.unknown())),
  estimatedTokens: z.number(),
});
export type ScanDevicesOutput = z.infer<typeof ScanDevicesOutputSchema>;

interface RawScanResponse {
  scan_duration_seconds: number;
  adapter: string;
  device_count: number;
  devices: Array<Record<string, unknown>>;
}

export const scanDevices = {
  name: 'caeruleus.scan_devices',
  description:
    'Scan for BLE devices in range. Returns advertisement data including device names, UUIDs, manufacturer data, and signal strength.',
  parameters: scanDevicesParams,

  async execute(
    input: ScanDevicesInput,
    client?: IBleClient,
  ): Promise<ScanDevicesOutput> {
    const validated = scanDevicesParams.parse(input);

    const serverParams: Record<string, unknown> = {
      duration: validated.duration,
      adapter: validated.adapter,
      active: validated.active,
    };

    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    const raw = (await callFn('scan', serverParams)) as RawScanResponse;

    let devices = raw.devices;
    if (validated.target_mac) {
      const target = validated.target_mac.toUpperCase();
      devices = devices.map((d) => ({
        ...d,
        is_target:
          (d.mac_address as string).toUpperCase() === target,
      }));
    }

    const result: ScanDevicesOutput = {
      scanDurationSeconds: raw.scan_duration_seconds,
      adapter: raw.adapter,
      deviceCount: raw.device_count,
      devices,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return ScanDevicesOutputSchema.parse(result);
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  scanDevices
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
