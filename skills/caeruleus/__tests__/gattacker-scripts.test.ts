import { describe, it, expect, vi } from 'vitest';
import type { IGattackerClient } from '../mitm-relay.js';
import { mitmRelay } from '../mitm-relay.js';
import { spoofNotifications } from '../spoof-notifications.js';

// ---------------------------------------------------------------------------
// Mock Gattacker WebSocket client
// ---------------------------------------------------------------------------
function createMockGattacker(
  scenario: {
    scanDevices?: Array<Record<string, unknown>>;
    hookEvents?: Array<Record<string, unknown>>;
  } = {},
): IGattackerClient & { sentMessages: Array<Record<string, unknown>> } {
  const sentMessages: Array<Record<string, unknown>> = [];
  let handler: ((msg: Record<string, unknown>) => void) | null = null;
  let hookEventIdx = 0;

  const client = {
    sentMessages,
    send: vi.fn((msg: Record<string, unknown>) => {
      sentMessages.push(msg);
      const action = msg.action as string;

      // Simulate responses based on action
      if (action === 'status') {
        setTimeout(() => handler?.({ state: 0, hooks_enabled: false }), 1);
      } else if (action === 'scan') {
        setTimeout(() => handler?.({ scan_done: true }), 1);
      } else if (action === 'results') {
        setTimeout(
          () =>
            handler?.({
              results: scenario.scanDevices || [
                { id: 0, mac: 'AA:BB:CC:DD:EE:FF', name: 'Target', rssi: -50 },
              ],
            }),
          1,
        );
      } else if (action === 'enable_hooks') {
        setTimeout(() => handler?.({ state: 0, hooks_enabled: true }), 1);
      } else if (action === 'start') {
        setTimeout(() => {
          handler?.({ state: 3 });
          // Send hook events after attack starts (use queueMicrotask for sync delivery)
          const events = scenario.hookEvents || [];
          for (const evt of events.slice(hookEventIdx)) {
            hookEventIdx++;
            queueMicrotask(() => handler?.(evt));
          }
        }, 1);
      } else if (action === 'stop') {
        setTimeout(() => handler?.({ state: 0 }), 1);
      } else if (action === 'hookret') {
        // No response needed for hook returns
      }
    }),
    onMessage(h: (msg: Record<string, unknown>) => void) {
      handler = h;
    },
    close: vi.fn(),
  };

  return client;
}

// ---------------------------------------------------------------------------
// mitm-relay
// ---------------------------------------------------------------------------
describe('mitmRelay', () => {
  it('performs full MITM relay flow and captures operations', async () => {
    const client = createMockGattacker({
      scanDevices: [
        { id: 0, mac: 'AA:BB:CC:DD:EE:FF', name: 'Target', rssi: -45 },
      ],
      hookEvents: [
        { onWrite: true, uuid: '2a00', value: 'AABB' },
        { onRead: true, uuid: '2a01', value: 'CCDD' },
      ],
    });

    const result = await mitmRelay.execute(
      {
        target_mac: 'AA:BB:CC:DD:EE:FF',
        capture_duration_seconds: 0,
        enable_hooks: true,
      },
      client,
    );

    expect(result.target_found).toBe(true);
    expect(result.attack_started).toBe(true);
    expect(result.captured_operation_count).toBe(2);
    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'mitm_relay_success')).toBe(true);
    expect(findings.some((f) => f.type === 'mitm_intercepted_characteristics')).toBe(true);
    expect(client.close).toHaveBeenCalled();
  });

  it('reports target not found when device not in scan results', async () => {
    const client = createMockGattacker({
      scanDevices: [
        { id: 0, mac: '11:22:33:44:55:66', name: 'Other', rssi: -70 },
      ],
    });

    const result = await mitmRelay.execute(
      {
        target_mac: 'AA:BB:CC:DD:EE:FF',
        capture_duration_seconds: 0,
      },
      client,
    );

    expect(result.target_found).toBe(false);
    expect(result.attack_started).toBe(false);
    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'mitm_target_not_found')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// spoof-notifications
// ---------------------------------------------------------------------------
describe('spoofNotifications', () => {
  it('spoofs read responses for targeted characteristics', async () => {
    const client = createMockGattacker({
      scanDevices: [
        { id: 0, mac: 'AA:BB:CC:DD:EE:FF', name: 'Target', rssi: -45 },
      ],
      hookEvents: [
        { onRead: true, uuid: '2a00', value: 'AABB' },
        { onRead: true, uuid: '2a00', value: 'CCDD' },
        { onRead: true, uuid: '2a01', value: 'EEFF' },
      ],
    });

    const result = await spoofNotifications.execute(
      {
        target_mac: 'AA:BB:CC:DD:EE:FF',
        capture_duration_seconds: 0,
        spoofed_values: [
          { uuid: '2a00', spoofed_value_hex: 'DEAD', description: 'Spoofed device name' },
        ],
      },
      client,
    );

    expect(result.target_found).toBe(true);
    expect(result.spoof_event_count).toBe(2); // Only 2a00 reads are spoofed
    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'notification_spoofing_success')).toBe(true);
    expect(findings.some((f) => f.type === 'spoofed_characteristic')).toBe(true);

    // Verify the hookret was sent with spoofed value for 2a00
    const hookrets = client.sentMessages.filter((m) => m.action === 'hookret');
    const spoofedHookret = hookrets.find((m) => m.hook_ret === 'DEAD');
    expect(spoofedHookret).toBeDefined();
  });

  it('reports target not found', async () => {
    const client = createMockGattacker({
      scanDevices: [
        { id: 0, mac: '11:22:33:44:55:66', name: 'Other', rssi: -70 },
      ],
    });

    const result = await spoofNotifications.execute(
      {
        target_mac: 'AA:BB:CC:DD:EE:FF',
        capture_duration_seconds: 0,
        spoofed_values: [
          { uuid: '2a00', spoofed_value_hex: 'DEAD' },
        ],
      },
      client,
    );

    expect(result.target_found).toBe(false);
  });

  it('reports no reads intercepted when no hook events fire', async () => {
    const client = createMockGattacker({
      scanDevices: [
        { id: 0, mac: 'AA:BB:CC:DD:EE:FF', name: 'Target', rssi: -45 },
      ],
      hookEvents: [],
    });

    const result = await spoofNotifications.execute(
      {
        target_mac: 'AA:BB:CC:DD:EE:FF',
        capture_duration_seconds: 0,
        spoofed_values: [
          { uuid: '2a00', spoofed_value_hex: 'DEAD' },
        ],
      },
      client,
    );

    expect(result.spoof_event_count).toBe(0);
    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'no_reads_intercepted')).toBe(true);
  });
});
