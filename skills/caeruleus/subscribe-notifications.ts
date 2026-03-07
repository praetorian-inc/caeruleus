/**
 * subscribe-notifications.ts — Notification/indication traffic capture (Flow 2.3)
 *
 * Subscribes to all notify/indicate characteristics, captures traffic over time,
 * identifies sensitive data in cleartext notifications.
 * Online: requires caeruleus-server.py (Async Choreography pattern)
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

export const subscribeNotificationsParams = z.object({
  mac_address: BleMacAddressSchema,
  gatt_map_path: z.string().optional(),
  uuids: z.array(z.string()).optional(),
  duration: z.number().min(1).max(3600).default(30),
  write_handle: z.number().optional(),
  write_value_hex: z.string().optional(),
  raw: z.boolean().default(false),
});
export type SubscribeNotificationsInput = z.infer<typeof subscribeNotificationsParams>;

// Patterns that indicate sensitive data in notification payloads
const SENSITIVE_PATTERNS = [
  { name: 'GPS Coordinates', pattern: /[-+]?\d{1,3}\.\d{4,}/ },
  { name: 'Temperature', pattern: /\d{2,3}\.\d{1,2}/ },
  { name: 'Email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
  { name: 'Phone Number', pattern: /\+?\d{10,15}/ },
  { name: 'Auth Token', pattern: /[a-fA-F0-9]{32,}/ },
];

export const subscribeNotifications = {
  name: 'caeruleus.subscribe_notifications',
  description:
    'Subscribe to BLE notification/indication characteristics and capture traffic. Identifies sensitive data in cleartext.',
  parameters: subscribeNotificationsParams,

  async execute(
    input: SubscribeNotificationsInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = subscribeNotificationsParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    // Ensure connected
    await callFn('connect', { mac_address: validated.mac_address });

    // Warn on macOS — CoreBluetooth cannot enable notifications when the
    // remote device lacks CCCD descriptors (common in CTF / non-compliant firmware).
    const isMacOS = process.platform === 'darwin';
    const macosWarning = isMacOS
      ? 'WARNING: Running on macOS/CoreBluetooth. Notification/indication '
        + 'subscriptions may fail if the remote device lacks CCCD descriptors '
        + '(0x2902). For full compatibility, use Linux/BlueZ.'
      : null;

    // Determine which UUIDs to subscribe to
    let targetUuids = validated.uuids || [];

    if (targetUuids.length === 0 && validated.gatt_map_path) {
      const gattRaw = await readFile(validated.gatt_map_path, 'utf-8');
      const gattMap = JSON.parse(gattRaw);
      for (const svc of gattMap.services || []) {
        for (const char of svc.characteristics || []) {
          if (char.properties?.notify || char.properties?.indicate) {
            targetUuids.push(char.uuid);
          }
        }
      }
    }

    if (targetUuids.length === 0) {
      return {
        error: 'No notifiable/indicatable characteristics found',
        suggestion: 'Provide uuids array or gatt_map_path with notify/indicate characteristics',
      };
    }

    const captures: Array<Record<string, unknown>> = [];
    const findings: Array<Record<string, unknown>> = [];

    for (const uuid of targetUuids) {
      try {
        const serverCommand = validated.raw ? 'subscribe_raw' : 'subscribe';
        const subParams: Record<string, unknown> = {
          mac_address: validated.mac_address,
          uuid,
          duration: validated.duration,
          timeout_ms: (validated.duration + 60) * 1000,
        };
        if (validated.write_handle !== undefined) {
          subParams.write_handle = validated.write_handle;
        }
        if (validated.write_value_hex !== undefined) {
          subParams.write_value_hex = validated.write_value_hex;
        }
        const subResult = (await callFn(serverCommand, subParams)) as Record<string, unknown>;

        const notifications = (subResult.notifications as Array<Record<string, unknown>>) || [];

        // Analyze each notification for sensitive data
        const sensitiveHits: Array<Record<string, unknown>> = [];
        for (const notif of notifications) {
          const decoded = notif.decoded as string | null;
          if (decoded) {
            for (const sp of SENSITIVE_PATTERNS) {
              if (sp.pattern.test(decoded)) {
                sensitiveHits.push({
                  pattern: sp.name,
                  value: decoded,
                  timestamp: notif.timestamp,
                });
              }
            }
          }
        }

        captures.push({
          uuid,
          notification_count: notifications.length,
          notifications,
          sensitive_data_detected: sensitiveHits.length > 0,
          sensitive_hits: sensitiveHits,
        });

        if (sensitiveHits.length > 0) {
          findings.push({
            type: 'cleartext_sensitive_data',
            severity: 'high',
            uuid,
            description: `Sensitive data detected in cleartext notifications from ${uuid}`,
            patterns_matched: sensitiveHits.map((h) => h.pattern),
          });
        }
      } catch (e) {
        captures.push({
          uuid,
          error: (e as Error).message,
          notification_count: 0,
        });
      }
    }

    const totalNotifications = captures.reduce(
      (sum, c) => sum + ((c.notification_count as number) || 0),
      0,
    );

    // Detect likely CCCD-less device: Bleak subscribe path returned 0
    // notifications or timed out on every characteristic.  Suggest raw mode.
    const allFailed = captures.every(
      (c) => (c.notification_count as number) === 0 || c.error,
    );
    const rawSuggestion =
      !validated.raw && allFailed && totalNotifications === 0
        ? 'All subscriptions returned 0 notifications. The device may lack CCCD '
          + 'descriptors (common in CTF boards and non-compliant IoT firmware). '
          + 'Retry with raw: true or use subscribe-raw directly for L2CAP ATT bypass.'
        : null;

    const result: Record<string, unknown> = {
      duration_seconds: validated.duration,
      characteristics_monitored: targetUuids.length,
      captures,
      findings,
      total_notifications: totalNotifications,
      ...(macosWarning ? { platform_warning: macosWarning } : {}),
      ...(rawSuggestion ? { suggestion: rawSuggestion } : {}),
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  subscribeNotifications
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
