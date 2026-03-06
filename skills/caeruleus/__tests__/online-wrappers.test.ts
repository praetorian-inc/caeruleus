import { describe, it, expect, vi } from 'vitest';
import type { IBleClient, CaeruleusCallParams } from '../lib/types.js';
import { scanDevices } from '../scan-devices.js';
import { testPairing } from '../test-pairing.js';
import { fuzzCharacteristic } from '../fuzz-characteristic.js';
import { replayWrites } from '../replay-writes.js';
import { analyzeConnectionParams } from '../analyze-connection-params.js';
import { testWwrAbuse } from '../test-wwr-abuse.js';
import { readCharacteristic } from '../read-characteristic.js';
import { writeCharacteristic } from '../write-characteristic.js';
import { testDfu } from '../test-dfu.js';

// ---------------------------------------------------------------------------
// Mock BLE client factory
// ---------------------------------------------------------------------------
function createMockClient(
  responses: Record<string, unknown>,
): IBleClient {
  return {
    call: vi.fn(async (params: CaeruleusCallParams) => {
      const key = params.command;
      if (key in responses) {
        const val = responses[key];
        if (typeof val === 'function') return val(params.params);
        return val;
      }
      throw new Error(`Unmocked command: ${key}`);
    }),
    ping: vi.fn(async () => ({ pong: true, connected: true })),
    shutdown: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// scan-devices
// ---------------------------------------------------------------------------
describe('scanDevices', () => {
  it('returns scanned devices from server', async () => {
    const client = createMockClient({
      scan: {
        scan_duration_seconds: 10,
        adapter: 'hci0',
        device_count: 2,
        devices: [
          { mac_address: 'AA:BB:CC:DD:EE:FF', device_name: 'Device1' },
          { mac_address: '11:22:33:44:55:66', device_name: 'Device2' },
        ],
      },
    });

    const result = await scanDevices.execute(
      { duration: 10, adapter: 'hci0', active: false },
      client,
    );

    expect(result.deviceCount).toBe(2);
    expect(result.devices).toHaveLength(2);
    expect(result.estimatedTokens).toBeGreaterThan(0);
    expect(client.call).toHaveBeenCalledOnce();
  });

  it('marks target device when target_mac is specified', async () => {
    const client = createMockClient({
      scan: {
        scan_duration_seconds: 5,
        adapter: 'hci0',
        device_count: 2,
        devices: [
          { mac_address: 'AA:BB:CC:DD:EE:FF', device_name: 'Target' },
          { mac_address: '11:22:33:44:55:66', device_name: 'Other' },
        ],
      },
    });

    const result = await scanDevices.execute(
      { duration: 5, target_mac: 'AA:BB:CC:DD:EE:FF' },
      client,
    );

    const target = result.devices.find(
      (d) => (d as Record<string, unknown>).is_target === true,
    );
    expect(target).toBeDefined();
    expect((target as Record<string, unknown>).mac_address).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('applies Zod defaults', async () => {
    const client = createMockClient({
      scan: { scan_duration_seconds: 10, adapter: 'hci0', device_count: 0, devices: [] },
    });

    const result = await scanDevices.execute({}, client);
    expect(result.scanDurationSeconds).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// test-pairing
// ---------------------------------------------------------------------------
describe('testPairing', () => {
  it('detects pairing not enforced when chars accessible without pairing', async () => {
    const client = createMockClient({
      connect: { connected: true },
      test_encryption: {
        unencrypted_characteristics: ['2a00', '2a01'],
        encrypted_characteristics: [],
      },
      pair: { paired: true, method: 'just_works' },
      unpair: { unpaired: true },
    });

    const result = await testPairing.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF' },
      client,
    );

    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'pairing_not_enforced')).toBe(true);
    expect(findings[0].severity).toBe('high');
  });

  it('reports legacy fallback when chars accessible after unpair', async () => {
    const client = createMockClient({
      connect: { connected: true },
      test_encryption: {
        unencrypted_characteristics: ['2a00'],
        encrypted_characteristics: ['2a01'],
      },
      pair: { paired: true },
      unpair: { unpaired: true },
    });

    const result = await testPairing.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF', test_legacy_fallback: true },
      client,
    );

    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'legacy_fallback')).toBe(true);
  });

  it('skips enforcement test when disabled', async () => {
    const client = createMockClient({
      connect: { connected: true },
      pair: { paired: true },
    });

    const result = await testPairing.execute(
      {
        mac_address: 'AA:BB:CC:DD:EE:FF',
        test_enforcement: false,
        test_legacy_fallback: false,
      },
      client,
    );

    expect(result.pre_pair_tests).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// fuzz-characteristic
// ---------------------------------------------------------------------------
describe('fuzzCharacteristic', () => {
  it('reports crashes as high severity finding', async () => {
    const client = createMockClient({
      connect: { connected: true },
      fuzz_characteristic: {
        iterations_completed: 50,
        crashes: [
          { iteration: 42, input_hex: 'ffff', error: 'disconnect' },
        ],
        errors: [],
        start_time: '2026-01-01T00:00:00Z',
        end_time: '2026-01-01T00:01:00Z',
      },
    });

    const result = await fuzzCharacteristic.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF', uuid: '2a00', strategy: 'boundary', iterations: 100 },
      client,
    );

    expect(result.crashes_found).toBe(1);
    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings[0].severity).toBe('high');
    expect(findings[0].type).toBe('device_crash');
  });

  it('flags excessive errors as medium severity', async () => {
    const errors = Array.from({ length: 15 }, (_, i) => ({
      iteration: i,
      input_hex: 'aa',
      error: 'write failed',
    }));

    const client = createMockClient({
      connect: { connected: true },
      fuzz_characteristic: {
        iterations_completed: 100,
        crashes: [],
        errors,
        start_time: '2026-01-01T00:00:00Z',
        end_time: '2026-01-01T00:01:00Z',
      },
    });

    const result = await fuzzCharacteristic.execute({ mac_address: 'AA:BB:CC:DD:EE:FF', uuid: '2a00' }, client);
    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'excessive_errors')).toBe(true);
  });

  it('returns clean result with no crashes or errors', async () => {
    const client = createMockClient({
      connect: { connected: true },
      fuzz_characteristic: {
        iterations_completed: 100,
        crashes: [],
        errors: [],
        start_time: '2026-01-01T00:00:00Z',
        end_time: '2026-01-01T00:01:00Z',
      },
    });

    const result = await fuzzCharacteristic.execute({ mac_address: 'AA:BB:CC:DD:EE:FF', uuid: '2a00' }, client);
    expect(result.crashes_found).toBe(0);
    expect(result.errors_found).toBe(0);
    expect((result.findings as unknown[]).length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// replay-writes
// ---------------------------------------------------------------------------
describe('replayWrites', () => {
  it('detects missing replay protection', async () => {
    const client = createMockClient({
      connect: { connected: true },
      unpair: { unpaired: true },
      replay_writes: {
        total_replayed: 3,
        accepted: 3,
        rejected: 0,
        replay_protection: false,
        results: [
          { uuid: '2a00', value_hex: 'aa', accepted: true },
          { uuid: '2a01', value_hex: 'bb', accepted: true },
          { uuid: '2a02', value_hex: 'cc', accepted: true },
        ],
      },
    });

    const result = await replayWrites.execute(
      {
        mac_address: 'AA:BB:CC:DD:EE:FF',
        writes: [
          { uuid: '2a00', value_hex: 'aa' },
          { uuid: '2a01', value_hex: 'bb' },
          { uuid: '2a02', value_hex: 'cc' },
        ],
      },
      client,
    );

    expect(result.accepted).toBe(3);
    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('missing_replay_protection');
    expect(findings[0].severity).toBe('high');
  });

  it('produces no findings when all writes rejected', async () => {
    const client = createMockClient({
      connect: { connected: true },
      unpair: { unpaired: true },
      replay_writes: {
        total_replayed: 2,
        accepted: 0,
        rejected: 2,
        replay_protection: true,
        results: [
          { uuid: '2a00', value_hex: 'aa', accepted: false },
          { uuid: '2a01', value_hex: 'bb', accepted: false },
        ],
      },
    });

    const result = await replayWrites.execute(
      {
        mac_address: 'AA:BB:CC:DD:EE:FF',
        writes: [
          { uuid: '2a00', value_hex: 'aa' },
          { uuid: '2a01', value_hex: 'bb' },
        ],
      },
      client,
    );

    expect(result.accepted).toBe(0);
    expect((result.findings as unknown[]).length).toBe(0);
  });

  it('skips unpair when unpair_before_replay is false', async () => {
    const client = createMockClient({
      connect: { connected: true },
      replay_writes: {
        total_replayed: 1,
        accepted: 0,
        rejected: 1,
        replay_protection: true,
        results: [{ uuid: '2a00', value_hex: 'aa', accepted: false }],
      },
    });

    const result = await replayWrites.execute(
      {
        mac_address: 'AA:BB:CC:DD:EE:FF',
        writes: [{ uuid: '2a00', value_hex: 'aa' }],
        unpair_before_replay: false,
      },
      client,
    );

    expect(result.unpaired_before_replay).toBe(false);
    // unpair should not have been called
    const calls = (client.call as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls.every((c: unknown[]) => (c[0] as CaeruleusCallParams).command !== 'unpair')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// analyze-connection-params
// ---------------------------------------------------------------------------
describe('analyzeConnectionParams', () => {
  it('reports findings for weak connection parameters', async () => {
    const client = createMockClient({
      connect: { connected: true },
      get_connection_params: {
        connection_interval_ms: 500,
        slave_latency: 15,
        supervision_timeout_ms: 500,
        mtu: 23,
      },
    });

    const result = await analyzeConnectionParams.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF' },
      client,
    );

    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'slow_connection_interval')).toBe(true);
    expect(findings.some((f) => f.type === 'high_slave_latency')).toBe(true);
    expect(findings.some((f) => f.type === 'short_supervision_timeout')).toBe(true);
    expect(findings.some((f) => f.type === 'small_mtu')).toBe(true);
  });

  it('flags large MTU exposure', async () => {
    const client = createMockClient({
      connect: { connected: true },
      get_connection_params: {
        connection_interval_ms: 50,
        slave_latency: 0,
        supervision_timeout_ms: 5000,
        mtu: 512,
      },
    });

    const result = await analyzeConnectionParams.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF' },
      client,
    );

    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'large_mtu_exposure')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// test-wwr-abuse
// ---------------------------------------------------------------------------
describe('testWwrAbuse', () => {
  it('tests write-without-response characteristics', async () => {
    let writeCount = 0;
    const client = createMockClient({
      connect: { connected: true },
      get_gatt_map: {
        services: [
          {
            characteristics: [
              { uuid: 'test-uuid', properties: { write_no_response: true } },
            ],
          },
        ],
      },
      write_no_response: () => {
        writeCount++;
        return { success: true };
      },
    });

    const result = await testWwrAbuse.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF', rapid_fire_count: 5, max_write_sizes: [20, 50] },
      client,
    );

    expect(result.characteristics_tested).toBe(1);
    expect(writeCount).toBeGreaterThan(0);
  });

  it('detects crash during overflow test', async () => {
    let callCount = 0;
    const client = createMockClient({
      connect: { connected: true },
      write_no_response: () => {
        callCount++;
        if (callCount === 3) throw new Error('Device disconnect');
        return { success: true };
      },
    });

    const result = await testWwrAbuse.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF', uuids: ['test-uuid'], max_write_sizes: [20, 50, 100, 200], rapid_fire_count: 1 },
      client,
    );

    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'wwr_buffer_overflow')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// read-characteristic
// ---------------------------------------------------------------------------
describe('readCharacteristic', () => {
  it('reads characteristic value', async () => {
    const client = createMockClient({
      connect: { connected: true },
      read_characteristic: {
        value_hex: '48656c6c6f',
        value_decoded: 'Hello',
        encoding: 'utf-8',
      },
    });

    const result = await readCharacteristic.execute({ mac_address: 'AA:BB:CC:DD:EE:FF', uuid: '2a00' }, client);
    expect(result.value_hex).toBe('48656c6c6f');
    expect(result.value_decoded).toBe('Hello');
  });
});

// ---------------------------------------------------------------------------
// write-characteristic
// ---------------------------------------------------------------------------
describe('writeCharacteristic', () => {
  it('writes with response by default', async () => {
    const client = createMockClient({
      connect: { connected: true },
      write_characteristic: { success: true },
    });

    const result = await writeCharacteristic.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF', uuid: '2a00', value_hex: 'ff' },
      client,
    );

    expect(result.success).toBe(true);
    expect(result.response_mode).toBe(true);
    const calls = (client.call as ReturnType<typeof vi.fn>).mock.calls;
    expect((calls[1][0] as CaeruleusCallParams).command).toBe('write_characteristic');
  });

  it('uses write_no_response when response=false', async () => {
    const client = createMockClient({
      connect: { connected: true },
      write_no_response: { success: true },
    });

    const result = await writeCharacteristic.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF', uuid: '2a00', value_hex: 'ff', response: false },
      client,
    );

    expect(result.response_mode).toBe(false);
    const calls = (client.call as ReturnType<typeof vi.fn>).mock.calls;
    expect((calls[1][0] as CaeruleusCallParams).command).toBe('write_no_response');
  });
});

// ---------------------------------------------------------------------------
// test-dfu
// ---------------------------------------------------------------------------
describe('testDfu', () => {
  it('detects DFU service and reports exposure finding', async () => {
    const client = createMockClient({
      get_gatt_map: {
        services: [
          {
            uuid: '0000fe59-0000-1000-8000-00805f9b34fb',
            characteristics: [
              { uuid: '8ec90001-f315-4f60-9fb8-838830daea50' },
              { uuid: '8ec90002-f315-4f60-9fb8-838830daea50' },
              { uuid: '8ec90003-f315-4f60-9fb8-838830daea50' },
            ],
          },
        ],
      },
      subscribe: { subscribed: true },
      write_characteristic: { success: true },
      write_no_response: { success: true },
    });

    const result = await testDfu.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF' },
      client,
    );

    expect(result.dfu_present).toBe(true);
    expect(result.dfu_type).toBe('nordic');
    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'dfu_service_exposed')).toBe(true);
  });

  it('reports no DFU when service not found', async () => {
    const client = createMockClient({
      get_gatt_map: {
        services: [
          {
            uuid: '0000180a-0000-1000-8000-00805f9b34fb',
            characteristics: [{ uuid: '2a29' }],
          },
        ],
      },
    });

    const result = await testDfu.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF', test_buttonless: false, test_unsigned: false, test_downgrade: false },
      client,
    );

    expect(result.dfu_present).toBe(false);
    expect(result.findings_count).toBe(0);
  });

  it('detects unauthenticated buttonless DFU entry', async () => {
    const client = createMockClient({
      get_gatt_map: {
        services: [
          {
            uuid: '0000fe59-0000-1000-8000-00805f9b34fb',
            characteristics: [
              { uuid: '8ec90003-f315-4f60-9fb8-838830daea50' },
            ],
          },
        ],
      },
      subscribe: { subscribed: true },
      write_characteristic: { success: true },
    });

    const result = await testDfu.execute(
      { mac_address: 'AA:BB:CC:DD:EE:FF', test_unsigned: false, test_downgrade: false },
      client,
    );

    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'dfu_unauthenticated_entry')).toBe(true);
  });
});
