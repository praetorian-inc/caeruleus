/**
 * sniff-decode.ts — Passive BLE sniffing & decode (Flow 2.5)
 *
 * Orchestrates caeruleus-sniffer.py to capture over-the-air packets,
 * decodes LL and ATT layers, reconstructs GATT conversations.
 * Online: requires caeruleus-sniffer.py
 */

import { z } from 'zod';
import { spawn, type ChildProcess } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as YAML from 'yaml';
import { estimateTokens } from './lib/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DELIMITER = '\n---\n';

export const sniffDecodeParams = z.object({
  target_mac: z.string().optional(),
  duration: z.number().min(1).max(3600).default(30),
  mode: z.enum(['follow', 'advertisements_only']).default('follow'),
  output_file: z.string().default('/tmp/caeruleus-capture.pcap'),
  decode_filter: z.enum(['all', 'att', 'll', 'adv']).default('all'),
  max_packets: z.number().min(1).max(10000).default(100),
  hardware: z.string().optional(),
});
export type SniffDecodeInput = z.infer<typeof sniffDecodeParams>;

async function callSniffer(
  command: string,
  params: Record<string, unknown>,
  snifferProcess?: { call: (cmd: string, params: Record<string, unknown>) => Promise<unknown> },
): Promise<unknown> {
  if (snifferProcess) {
    return snifferProcess.call(command, params);
  }

  const serverPath = join(__dirname, 'caeruleus-sniffer.py');
  const python = process.env.CAERULEUS_PYTHON || 'python3';

  return new Promise<unknown>((resolve, reject) => {
    const proc = spawn(python, [serverPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        CAERULEUS_SNIFFER_HARDWARE: params.hardware as string || process.env.CAERULEUS_SNIFFER_HARDWARE || 'ubertooth',
      },
    });

    let buffer = '';
    let readyReceived = false;
    let requestSent = false;

    proc.stdout?.on('data', (data: Buffer) => {
      buffer += data.toString();

      let pos: number;
      while ((pos = buffer.indexOf(DELIMITER)) !== -1) {
        const yamlText = buffer.substring(0, pos);
        buffer = buffer.substring(pos + DELIMITER.length);
        if (!yamlText.trim()) continue;

        const response = YAML.parse(yamlText);

        if (!readyReceived && response.result?.ready) {
          readyReceived = true;
          // Send command
          const request = YAML.stringify({ id: 1, command, params });
          proc.stdin!.write(request + DELIMITER);
          requestSent = true;
          continue;
        }

        if (requestSent && response.id === 1) {
          // Send shutdown
          const shutdown = YAML.stringify({ id: 2, command: 'shutdown', params: {} });
          proc.stdin!.write(shutdown + DELIMITER);

          if (response.status === 'ok') {
            resolve(response.result);
          } else {
            reject(new Error(response.error?.message || 'Sniffer error'));
          }
        }
      }
    });

    proc.on('exit', () => {
      if (!requestSent) reject(new Error('Sniffer exited before ready'));
    });

    proc.on('error', (err) => reject(err));

    setTimeout(() => {
      proc.kill();
      reject(new Error('Sniffer timeout'));
    }, 120_000);
  });
}

export const sniffDecode = {
  name: 'caeruleus.sniff_decode',
  description:
    'Capture and decode BLE packets using Ubertooth/nRF52/Sniffle hardware. Produces decoded packet summaries.',
  parameters: sniffDecodeParams,

  async execute(input: SniffDecodeInput): Promise<Record<string, unknown>> {
    const validated = sniffDecodeParams.parse(input);

    // Start capture
    const captureResult = (await callSniffer('start_capture', {
      target_mac: validated.target_mac,
      duration: validated.duration,
      mode: validated.mode,
      output_file: validated.output_file,
      hardware: validated.hardware,
    })) as Record<string, unknown>;

    // Wait for duration
    await new Promise((resolve) => setTimeout(resolve, validated.duration * 1000));

    // Stop capture
    const stopResult = (await callSniffer('stop_capture', {})) as Record<string, unknown>;

    // Decode packets
    let decodeResult: Record<string, unknown> = {};
    try {
      decodeResult = (await callSniffer('decode_packets', {
        pcap_file: validated.output_file,
        max_packets: validated.max_packets,
        filter: validated.decode_filter,
      })) as Record<string, unknown>;
    } catch {
      decodeResult = { packet_count: 0, packets: [], error: 'tshark not available' };
    }

    const findings: Array<Record<string, unknown>> = [];

    // Check for unencrypted traffic
    const packets = (decodeResult.packets || []) as Array<Record<string, unknown>>;
    if (packets.length > 0) {
      const hasUnencrypted = packets.some(
        (p) => JSON.stringify(p).includes('btatt') && !JSON.stringify(p).includes('btle.encrypted'),
      );
      if (hasUnencrypted) {
        findings.push({
          type: 'unencrypted_traffic',
          severity: 'high',
          description: 'Unencrypted ATT traffic detected in over-the-air capture',
        });
      }
    }

    const result = {
      schema_version: '1.0',
      capture: captureResult,
      stop: stopResult,
      decode: decodeResult,
      packet_count: decodeResult.packet_count || 0,
      output_file: validated.output_file,
      duration: validated.duration,
      mode: validated.mode,
      target_mac: validated.target_mac,
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
  sniffDecode
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
