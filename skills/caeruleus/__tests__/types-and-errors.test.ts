import { describe, it, expect } from 'vitest';
import {
  BleMacAddressSchema,
  BleScanParamsSchema,
  BleConnectParamsSchema,
  BleReadCharParamsSchema,
  BleWriteCharParamsSchema,
  BleSubscribeParamsSchema,
  BleFuzzCharParamsSchema,
  BleDiscoveredDeviceSchema,
  BleGattMapSchema,
  BleFindingSchema,
  BleSecurityPostureSchema,
  BleEngagementConfigSchema,
  BleOperatorInteractionSchema,
  estimateTokens,
} from '../lib/types.js';
import {
  BleError,
  BleAdapterNotFoundError,
  BleDeviceNotFoundError,
  BleConnectionLostError,
  BleDeviceCrashedError,
  BleTimeoutError,
  BleServerNotRunningError,
} from '../lib/errors.js';

// ---------------------------------------------------------------------------
// estimateTokens
// ---------------------------------------------------------------------------
describe('estimateTokens', () => {
  it('estimates tokens from a string', () => {
    const tokens = estimateTokens('hello world');
    expect(tokens).toBe(Math.ceil(11 / 3.2));
  });

  it('estimates tokens from an object via JSON.stringify', () => {
    const obj = { key: 'value', nested: { a: 1 } };
    const tokens = estimateTokens(obj);
    expect(tokens).toBe(Math.ceil(JSON.stringify(obj).length / 3.2));
  });

  it('returns 1 for empty string', () => {
    expect(estimateTokens('')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// MAC Address Schema
// ---------------------------------------------------------------------------
describe('BleMacAddressSchema', () => {
  it('accepts valid MAC', () => {
    expect(BleMacAddressSchema.parse('AA:BB:CC:DD:EE:FF')).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('accepts CoreBluetooth UUID (macOS)', () => {
    const uuid = '6F4AC8F1-826E-5069-E900-8C09B5C6CBDA';
    expect(BleMacAddressSchema.parse(uuid)).toBe(uuid);
  });

  it('rejects short MAC', () => {
    expect(() => BleMacAddressSchema.parse('AA:BB:CC')).toThrow();
  });

  it('rejects MAC without colons', () => {
    expect(() => BleMacAddressSchema.parse('AABBCCDDEEFF')).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Input parameter schemas
// ---------------------------------------------------------------------------
describe('BleScanParamsSchema', () => {
  it('applies defaults', () => {
    const result = BleScanParamsSchema.parse({});
    expect(result.duration).toBe(10);
    expect(result.adapter).toBe('hci0');
    expect(result.active).toBe(false);
  });

  it('rejects out-of-range duration', () => {
    expect(() => BleScanParamsSchema.parse({ duration: 500 })).toThrow();
    expect(() => BleScanParamsSchema.parse({ duration: 0 })).toThrow();
  });
});

describe('BleConnectParamsSchema', () => {
  it('parses valid input with defaults', () => {
    const result = BleConnectParamsSchema.parse({ mac_address: '11:22:33:44:55:66' });
    expect(result.mac_type).toBe('public');
    expect(result.timeout).toBe(15);
  });

  it('rejects invalid MAC', () => {
    expect(() => BleConnectParamsSchema.parse({ mac_address: 'invalid' })).toThrow();
  });
});

describe('BleWriteCharParamsSchema', () => {
  it('rejects non-hex value', () => {
    expect(() =>
      BleWriteCharParamsSchema.parse({ uuid: '2a00', value_hex: 'ZZZZ' }),
    ).toThrow();
  });

  it('accepts valid hex', () => {
    const result = BleWriteCharParamsSchema.parse({ uuid: '2a00', value_hex: 'deadbeef' });
    expect(result.value_hex).toBe('deadbeef');
    expect(result.response).toBe(true);
  });
});

describe('BleFuzzCharParamsSchema', () => {
  it('applies defaults', () => {
    const result = BleFuzzCharParamsSchema.parse({ uuid: '2a00' });
    expect(result.strategy).toBe('type_aware');
    expect(result.iterations).toBe(100);
    expect(result.delay_ms).toBe(50);
  });

  it('rejects iterations over max', () => {
    expect(() =>
      BleFuzzCharParamsSchema.parse({ uuid: '2a00', iterations: 50000 }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Output schemas — BleDiscoveredDevice
// ---------------------------------------------------------------------------
describe('BleDiscoveredDeviceSchema', () => {
  const validDevice = {
    mac_address: 'AA:BB:CC:DD:EE:FF',
    mac_type: 'public' as const,
    device_name: 'Test Device',
    rssi_dbm: -55,
    tx_power_dbm: null,
    connectable: true,
    service_uuids: ['180a', '180f'],
    first_seen: '2026-01-01T00:00:00Z',
    last_seen: '2026-01-01T00:00:10Z',
  };

  it('parses valid device', () => {
    const result = BleDiscoveredDeviceSchema.parse(validDevice);
    expect(result.is_target).toBe(false);
    expect(result.mac_address).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('rejects missing required fields', () => {
    expect(() => BleDiscoveredDeviceSchema.parse({ mac_address: 'AA:BB:CC:DD:EE:FF' })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// BleEngagementConfigSchema
// ---------------------------------------------------------------------------
describe('BleEngagementConfigSchema', () => {
  it('parses minimal valid config', () => {
    const config = {
      engagement_id: 'ENG-001',
      target: {
        device_name: 'Smart Lock',
        mac_address: 'AA:BB:CC:DD:EE:FF',
        mac_type: 'public',
      },
      scope: {},
      operator: { name: 'Test Operator', engagement_ref: 'REF-001' },
    };
    const result = BleEngagementConfigSchema.parse(config);
    expect(result.schema_version).toBe('1.0');
    expect(result.scope.phases).toEqual([1, 2, 3, 4]);
  });
});

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------
describe('BleError', () => {
  it('constructs with code and message', () => {
    const err = new BleError('TIMEOUT', 'timed out', true, 'retry');
    expect(err.code).toBe('TIMEOUT');
    expect(err.message).toBe('timed out');
    expect(err.recoverable).toBe(true);
    expect(err.suggestion).toBe('retry');
    expect(err.name).toBe('BleError');
    expect(err).toBeInstanceOf(Error);
  });

  it('defaults to non-recoverable', () => {
    const err = new BleError('UNKNOWN', 'unknown error');
    expect(err.recoverable).toBe(false);
  });
});

describe('BleAdapterNotFoundError', () => {
  it('has correct code and default adapter', () => {
    const err = new BleAdapterNotFoundError();
    expect(err.code).toBe('ADAPTER_NOT_FOUND');
    expect(err.message).toContain('hci0');
    expect(err.recoverable).toBe(false);
  });

  it('uses custom adapter name', () => {
    const err = new BleAdapterNotFoundError('hci1');
    expect(err.message).toContain('hci1');
  });
});

describe('BleDeviceNotFoundError', () => {
  it('includes MAC in message', () => {
    const err = new BleDeviceNotFoundError('AA:BB:CC:DD:EE:FF');
    expect(err.code).toBe('DEVICE_NOT_FOUND');
    expect(err.message).toContain('AA:BB:CC:DD:EE:FF');
    expect(err.recoverable).toBe(true);
  });
});

describe('BleConnectionLostError', () => {
  it('includes reason when provided', () => {
    const err = new BleConnectionLostError('AA:BB:CC:DD:EE:FF', 'timeout');
    expect(err.message).toContain('timeout');
  });

  it('works without reason', () => {
    const err = new BleConnectionLostError('AA:BB:CC:DD:EE:FF');
    expect(err.message).toContain('AA:BB:CC:DD:EE:FF');
  });
});

describe('BleDeviceCrashedError', () => {
  it('has correct code', () => {
    const err = new BleDeviceCrashedError('AA:BB:CC:DD:EE:FF', '\\xff\\xff');
    expect(err.code).toBe('DEVICE_CRASHED');
    expect(err.message).toContain('crashed');
  });
});

describe('BleTimeoutError', () => {
  it('includes operation and timeout', () => {
    const err = new BleTimeoutError('scan', 5000);
    expect(err.code).toBe('TIMEOUT');
    expect(err.message).toContain('scan');
    expect(err.message).toContain('5000');
  });
});

describe('BleServerNotRunningError', () => {
  it('has fixed code and message', () => {
    const err = new BleServerNotRunningError();
    expect(err.code).toBe('SERVER_NOT_RUNNING');
    expect(err.recoverable).toBe(true);
  });
});
