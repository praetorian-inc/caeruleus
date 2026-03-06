import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fingerprintDevice } from '../fingerprint-device.js';
import { analyzeAdvertisements } from '../analyze-advertisements.js';
import { auditGattProfile } from '../audit-gatt-profile.js';
import { correlateFindings } from '../correlate-findings.js';
import { generateReport } from '../generate-report.js';
import { generateFuzzHarness } from '../generate-fuzz-harness.js';
import { visualizeGatt } from '../visualize-gatt.js';
import { mapCves } from '../map-cves.js';
import { assembleEvidence } from '../assemble-evidence.js';
import { generateRemediation } from '../generate-remediation.js';

let testDir: string;

beforeEach(async () => {
  testDir = join(tmpdir(), `caeruleus-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(testDir, { recursive: true });
});

afterEach(async () => {
  await rm(testDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const DEVICE_INVENTORY = {
  devices: [
    {
      mac_address: 'AA:BB:CC:DD:EE:FF',
      mac_type: 'public',
      device_name: 'SmartLock-SN123456',
      rssi_dbm: -55,
      tx_power_dbm: -20,
      connectable: true,
      service_uuids: ['180a', '180f'],
      manufacturer_data: { '0x0059': '0102030405' },
      is_target: true,
      first_seen: '2026-01-01T00:00:00Z',
      last_seen: '2026-01-01T00:00:10Z',
      advertisement_count: 5,
    },
  ],
};

const GATT_MAP = {
  schema_version: '1.0',
  device_mac: 'AA:BB:CC:DD:EE:FF',
  connection_timestamp: '2026-01-01T00:00:00Z',
  mtu: 23,
  services: [
    {
      uuid: '0000180a-0000-1000-8000-00805f9b34fb',
      uuid_short: '180a',
      name: 'Device Information',
      type: 'standard',
      handle_start: '0x0001',
      handle_end: '0x0010',
      characteristics: [
        {
          uuid: '00002a24-0000-1000-8000-00805f9b34fb',
          uuid_short: '2a24',
          name: 'Model Number String',
          handle: '0x0002',
          value_handle: '0x0003',
          properties: {
            broadcast: false, read: true, write_no_response: false,
            write: false, notify: false, indicate: false,
            authenticated_signed_writes: false, extended_properties: false,
          },
          security: { read_requires: 'none', write_requires: 'none' },
          value: { raw_hex: '4d6f64656c31', decoded: 'Model1', encoding: 'utf-8' },
          descriptors: [],
        },
      ],
    },
    {
      uuid: '12345678-1234-1234-1234-123456789abc',
      uuid_short: null,
      name: null,
      type: 'custom',
      handle_start: '0x0020',
      handle_end: '0x0030',
      characteristics: [
        {
          uuid: 'abcd1234-abcd-abcd-abcd-abcd12345678',
          uuid_short: null,
          name: null,
          handle: '0x0021',
          value_handle: '0x0022',
          properties: {
            broadcast: false, read: true, write_no_response: false,
            write: true, notify: false, indicate: false,
            authenticated_signed_writes: false, extended_properties: false,
          },
          security: { read_requires: 'none', write_requires: 'none' },
          value: null,
          descriptors: [],
        },
      ],
    },
  ],
  summary: {
    total_services: 2, standard_services: 1, custom_services: 1,
    total_characteristics: 2, readable: 2, writable: 1, notifiable: 0, indicatable: 0,
  },
};

async function writeFixture(filename: string, data: unknown): Promise<string> {
  const path = join(testDir, filename);
  await writeFile(path, JSON.stringify(data), 'utf-8');
  return path;
}

// ---------------------------------------------------------------------------
// fingerprint-device
// ---------------------------------------------------------------------------
describe('fingerprintDevice', () => {
  it('identifies Nordic chipset from manufacturer data', async () => {
    const invPath = await writeFixture('inventory.json', DEVICE_INVENTORY);
    const result = await fingerprintDevice.execute({ device_inventory_path: invPath });

    expect(result.chipset).toEqual(
      expect.objectContaining({
        identified: true,
        company: 'Nordic Semiconductor',
        chipset_family: 'nRF5x',
      }),
    );
    expect((result.known_cves as string[]).length).toBeGreaterThan(0);
    expect(result.target_mac).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('detects public MAC type', async () => {
    const invPath = await writeFixture('inventory.json', DEVICE_INVENTORY);
    const result = await fingerprintDevice.execute({ device_inventory_path: invPath });

    expect(result.mac_analysis).toEqual(
      expect.objectContaining({ type: 'public' }),
    );
  });

  it('detects DFU service from GATT map', async () => {
    const invPath = await writeFixture('inventory.json', DEVICE_INVENTORY);
    const gattWithDfu = {
      ...GATT_MAP,
      services: [
        ...GATT_MAP.services,
        {
          uuid: '0000fe59-0000-1000-8000-00805f9b34fb',
          uuid_short: 'fe59',
          name: 'Nordic DFU',
          type: 'standard',
          handle_start: '0x0040',
          handle_end: '0x0050',
          characteristics: [],
        },
      ],
    };
    const gattPath = await writeFixture('gatt.json', gattWithDfu);
    const result = await fingerprintDevice.execute({
      device_inventory_path: invPath,
      gatt_map_path: gattPath,
    });

    expect(result.dfu_detected).toEqual(
      expect.objectContaining({ present: true, type: 'Nordic DFU (Secure)' }),
    );
  });

  it('returns error when no target found', async () => {
    const emptyInv = await writeFixture('empty.json', { devices: [] });
    const result = await fingerprintDevice.execute({ device_inventory_path: emptyInv });
    expect(result.error).toContain('No target device found');
  });

  it('includes estimatedTokens', async () => {
    const invPath = await writeFixture('inventory.json', DEVICE_INVENTORY);
    const result = await fingerprintDevice.execute({ device_inventory_path: invPath });
    expect(result.estimatedTokens).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// analyze-advertisements
// ---------------------------------------------------------------------------
describe('analyzeAdvertisements', () => {
  it('detects serial number leakage in device name', async () => {
    const invPath = await writeFixture('inventory.json', DEVICE_INVENTORY);
    const result = await analyzeAdvertisements.execute({ device_inventory_path: invPath });

    expect(result.total_leakage_findings).toBeGreaterThan(0);
    const analyses = result.analyses as Array<Record<string, unknown>>;
    const leaks = analyses[0].leakage_findings as Array<Record<string, unknown>>;
    expect(leaks.some((l) => l.type === 'Serial Number')).toBe(true);
  });

  it('flags public MAC as security concern', async () => {
    const invPath = await writeFixture('inventory.json', DEVICE_INVENTORY);
    const result = await analyzeAdvertisements.execute({ device_inventory_path: invPath });

    const analyses = result.analyses as Array<Record<string, unknown>>;
    const concerns = analyses[0].security_concerns as string[];
    expect(concerns.some((c) => c.includes('Public MAC'))).toBe(true);
  });

  it('flags connectable device', async () => {
    const invPath = await writeFixture('inventory.json', DEVICE_INVENTORY);
    const result = await analyzeAdvertisements.execute({ device_inventory_path: invPath });

    const analyses = result.analyses as Array<Record<string, unknown>>;
    const concerns = analyses[0].security_concerns as string[];
    expect(concerns.some((c) => c.includes('connectable'))).toBe(true);
  });

  it('filters by target_mac', async () => {
    const multiDevice = {
      devices: [
        ...DEVICE_INVENTORY.devices,
        {
          mac_address: '11:22:33:44:55:66',
          mac_type: 'random',
          device_name: 'Other',
          rssi_dbm: -70,
          tx_power_dbm: null,
          connectable: false,
          service_uuids: [],
          manufacturer_data: {},
          first_seen: '2026-01-01T00:00:00Z',
          last_seen: '2026-01-01T00:00:01Z',
        },
      ],
    };
    const invPath = await writeFixture('multi.json', multiDevice);
    const result = await analyzeAdvertisements.execute({
      device_inventory_path: invPath,
      target_mac: '11:22:33:44:55:66',
    });
    expect(result.devices_analyzed).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// audit-gatt-profile
// ---------------------------------------------------------------------------
describe('auditGattProfile', () => {
  it('identifies standard and custom services', async () => {
    const gattPath = await writeFixture('gatt.json', GATT_MAP);
    const result = await auditGattProfile.execute({ gatt_map_path: gattPath });

    expect(result.standard_services).toBe(1);
    expect(result.custom_services).toBe(1);
  });

  it('flags Device Information readable without encryption', async () => {
    const gattPath = await writeFixture('gatt.json', GATT_MAP);
    const result = await auditGattProfile.execute({ gatt_map_path: gattPath });

    const findings = result.findings as Array<Record<string, unknown>>;
    expect(findings.some((f) => f.type === 'information_disclosure')).toBe(true);
  });

  it('flags custom unauthenticated write as high severity', async () => {
    const gattPath = await writeFixture('gatt.json', GATT_MAP);
    const result = await auditGattProfile.execute({ gatt_map_path: gattPath });

    const findings = result.findings as Array<Record<string, unknown>>;
    const customWrite = findings.find((f) => f.type === 'custom_unauthenticated_write');
    expect(customWrite).toBeDefined();
    expect(customWrite!.severity).toBe('high');
  });

  it('includes schema_version and estimatedTokens', async () => {
    const gattPath = await writeFixture('gatt.json', GATT_MAP);
    const result = await auditGattProfile.execute({ gatt_map_path: gattPath });

    expect(result.schema_version).toBe('1.0');
    expect(result.estimatedTokens).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// correlate-findings
// ---------------------------------------------------------------------------
describe('correlateFindings', () => {
  it('aggregates and deduplicates findings across phases', async () => {
    const engDir = join(testDir, 'engagement');
    await mkdir(join(engDir, 'recon'), { recursive: true });
    await mkdir(join(engDir, 'analysis'), { recursive: true });

    await writeFile(
      join(engDir, 'recon', 'scan.json'),
      JSON.stringify({
        findings: [
          { type: 'info_leak', severity: 'medium', uuid: '2a00', description: 'Name leak' },
        ],
      }),
    );

    await writeFile(
      join(engDir, 'analysis', 'audit.json'),
      JSON.stringify({
        findings: [
          { type: 'info_leak', severity: 'high', uuid: '2a00', description: 'Name leak upgraded' },
          { type: 'unauth_write', severity: 'high', uuid: 'abcd', description: 'Writable' },
        ],
      }),
    );

    const result = await correlateFindings.execute({ engagement_dir: engDir });

    expect(result.total_raw_findings).toBe(3);
    expect(result.deduplicated_findings).toBe(2); // info_leak:2a00 deduped
    expect(result.duplicates_removed).toBe(1);
  });

  it('builds attack chains when multiple findings share uuid', async () => {
    const engDir = join(testDir, 'engagement');
    await mkdir(join(engDir, 'recon'), { recursive: true });

    await writeFile(
      join(engDir, 'recon', 'findings.json'),
      JSON.stringify({
        findings: [
          { type: 'info_leak', severity: 'medium', uuid: 'abcd', description: 'Read leak' },
          { type: 'unauth_write', severity: 'high', uuid: 'abcd', description: 'Write access' },
        ],
      }),
    );

    const result = await correlateFindings.execute({ engagement_dir: engDir });
    expect(result.attack_chain_count).toBe(1);
    const chains = result.attack_chains as Array<Record<string, unknown>>;
    expect(chains[0].target).toBe('abcd');
  });

  it('counts by severity', async () => {
    const engDir = join(testDir, 'engagement');
    await mkdir(join(engDir, 'attacks'), { recursive: true });

    await writeFile(
      join(engDir, 'attacks', 'fuzz.json'),
      JSON.stringify({
        findings: [
          { type: 'crash', severity: 'critical', uuid: '1234', description: 'Device crash' },
          { type: 'error', severity: 'low', uuid: '5678', description: 'Minor error' },
        ],
      }),
    );

    const result = await correlateFindings.execute({ engagement_dir: engDir });
    const bySeverity = result.by_severity as Record<string, number>;
    expect(bySeverity.critical).toBe(1);
    expect(bySeverity.low).toBe(1);
  });

  it('handles missing directories gracefully', async () => {
    const engDir = join(testDir, 'empty-engagement');
    await mkdir(engDir, { recursive: true });

    const result = await correlateFindings.execute({ engagement_dir: engDir });
    expect(result.total_raw_findings).toBe(0);
    expect(result.deduplicated_findings).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// generate-report
// ---------------------------------------------------------------------------
describe('generateReport', () => {
  it('generates markdown report from engagement artifacts', async () => {
    const engDir = join(testDir, 'engagement');
    await mkdir(join(engDir, 'config'), { recursive: true });
    await mkdir(join(engDir, 'reports'), { recursive: true });
    await mkdir(join(engDir, 'recon'), { recursive: true });
    await mkdir(join(engDir, 'analysis'), { recursive: true });

    await writeFile(
      join(engDir, 'config', 'engagement.json'),
      JSON.stringify({
        engagement_id: 'ENG-001',
        target: { device_name: 'TestLock', mac_address: 'AA:BB:CC:DD:EE:FF' },
        operator: { name: 'Tester' },
      }),
    );

    await writeFile(
      join(engDir, 'reports', 'correlated-findings.json'),
      JSON.stringify({
        findings: [
          { finding_id: 'F-001', severity: 'high', type: 'unauth_write', description: 'Write without auth' },
        ],
        by_severity: { high: 1 },
        attack_chains: [],
      }),
    );

    await writeFile(
      join(engDir, 'analysis', 'security-posture.json'),
      JSON.stringify({ overall_risk: 'high' }),
    );

    const result = await generateReport.execute({ engagement_dir: engDir });

    const md = result.report_markdown as string;
    expect(md).toContain('BLE Security Assessment Report');
    expect(md).toContain('ENG-001');
    expect(md).toContain('TestLock');
    expect(md).toContain('HIGH');
    expect(md).toContain('Write without auth');
    expect(result.findings_count).toBe(1);
  });

  it('handles missing artifacts gracefully', async () => {
    const engDir = join(testDir, 'empty-engagement');
    await mkdir(engDir, { recursive: true });

    const result = await generateReport.execute({ engagement_dir: engDir });
    const md = result.report_markdown as string;
    expect(md).toContain('BLE Security Assessment Report');
    expect(result.findings_count).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// generate-fuzz-harness
// ---------------------------------------------------------------------------
describe('generateFuzzHarness', () => {
  it('generates Python harness for writable characteristics', async () => {
    const gattPath = await writeFixture('gatt.json', GATT_MAP);
    const outDir = join(testDir, 'harnesses');

    const result = await generateFuzzHarness.execute({
      gatt_map_path: gattPath,
      output_dir: outDir,
      strategies: ['boundary', 'overflow'],
      iterations: 50,
    });

    expect(result.harnesses_generated).toBe(1); // Only the custom writable char
    const harnesses = result.harnesses as Array<Record<string, unknown>>;
    expect(harnesses[0].uuid).toBe('abcd1234-abcd-abcd-abcd-abcd12345678');
  });

  it('skips read-only characteristics', async () => {
    const readOnlyGatt = {
      ...GATT_MAP,
      services: [
        {
          ...GATT_MAP.services[0],
          characteristics: [GATT_MAP.services[0].characteristics[0]], // read-only
        },
      ],
    };
    const gattPath = await writeFixture('readonly.json', readOnlyGatt);
    const outDir = join(testDir, 'harnesses-ro');

    const result = await generateFuzzHarness.execute({
      gatt_map_path: gattPath,
      output_dir: outDir,
    });

    expect(result.harnesses_generated).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// visualize-gatt
// ---------------------------------------------------------------------------
describe('visualizeGatt', () => {
  it('generates text tree visualization', async () => {
    const gattPath = await writeFixture('gatt.json', GATT_MAP);
    const result = await visualizeGatt.execute({ gatt_map_path: gattPath, format: 'text' });

    const viz = result.visualization as string;
    expect(viz).toContain('Device Information');
    expect(viz).toContain('[STD]');
    expect(viz).toContain('[CUSTOM]');
    expect(viz).toContain('R');
    expect(result.services_count).toBe(2);
  });

  it('generates markdown visualization', async () => {
    const gattPath = await writeFixture('gatt.json', GATT_MAP);
    const result = await visualizeGatt.execute({ gatt_map_path: gattPath, format: 'markdown' });

    const viz = result.visualization as string;
    expect(viz).toContain('# GATT Map');
    expect(viz).toContain('## [STD]');
    expect(viz).toContain('## [CUSTOM]');
  });

  it('annotates findings when findings_path provided', async () => {
    const gattPath = await writeFixture('gatt.json', GATT_MAP);
    const findingsPath = await writeFixture('findings.json', {
      findings: [
        {
          uuid: 'abcd1234-abcd-abcd-abcd-abcd12345678',
          severity: 'high',
          description: 'Writable without auth',
        },
      ],
    });

    const result = await visualizeGatt.execute({
      gatt_map_path: gattPath,
      findings_path: findingsPath,
      format: 'text',
    });

    const viz = result.visualization as string;
    expect(viz).toContain('finding(s)');
  });
});

// ---------------------------------------------------------------------------
// map-cves
// ---------------------------------------------------------------------------
describe('mapCves', () => {
  it('matches Nordic chipset to known CVEs', async () => {
    const fpPath = await writeFixture('fingerprint.json', {
      target_mac: 'AA:BB:CC:DD:EE:FF',
      chipset: { identified: true, chipset_family: 'nRF5x', company: 'Nordic' },
    });

    const result = await mapCves.execute({ fingerprint_path: fpPath });

    expect(result.chipset_identified).toBe(true);
    expect(result.chipset_specific_cves).toBeGreaterThan(0);
    const cves = result.matched_cves as Array<Record<string, unknown>>;
    expect(cves.some((c) => (c.cve_id as string).includes('2019-17519'))).toBe(true);
  });

  it('includes generic BLE CVEs for unknown chipsets', async () => {
    const fpPath = await writeFixture('fingerprint.json', {
      target_mac: 'AA:BB:CC:DD:EE:FF',
      chipset: { identified: false },
    });

    const result = await mapCves.execute({ fingerprint_path: fpPath });
    expect(result.generic_ble_cves).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// assemble-evidence
// ---------------------------------------------------------------------------
describe('assembleEvidence', () => {
  it('collects artifacts from engagement directory', async () => {
    const engDir = join(testDir, 'eng');
    await mkdir(join(engDir, 'config'), { recursive: true });
    await mkdir(join(engDir, 'recon'), { recursive: true });
    await mkdir(join(engDir, 'reports', 'evidence'), { recursive: true });

    await writeFile(join(engDir, 'config', 'engagement.json'), JSON.stringify({ engagement_id: 'E-001' }));
    await writeFile(join(engDir, 'recon', 'gatt-map.json'), JSON.stringify({ services: [] }));
    await writeFile(join(engDir, 'recon', 'device-inventory.json'), JSON.stringify({ devices: [] }));

    const result = await assembleEvidence.execute({ engagement_dir: engDir });

    expect(result.total_artifacts).toBeGreaterThanOrEqual(3);
    expect(result.engagement_id).toBe('E-001');
    expect(result.manifest_path).toContain('evidence-manifest.json');
  });

  it('handles empty engagement directory', async () => {
    const engDir = join(testDir, 'empty-eng');
    await mkdir(engDir, { recursive: true });

    const result = await assembleEvidence.execute({ engagement_dir: engDir });
    expect(result.total_artifacts).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// generate-remediation
// ---------------------------------------------------------------------------
describe('generateRemediation', () => {
  it('generates remediation for each finding', async () => {
    const findingsPath = await writeFixture('correlated.json', {
      findings: [
        { finding_id: 'F-001', type: 'pairing_not_enforced', severity: 'high', description: 'No pairing' },
        { finding_id: 'F-002', type: 'device_crash', severity: 'high', uuid: '2a00', description: 'Crash on fuzz' },
        { finding_id: 'F-003', type: 'information_disclosure', severity: 'medium', description: 'Info leak' },
      ],
    });

    const result = await generateRemediation.execute({ findings_path: findingsPath });

    expect(result.total_remediations).toBe(3);
    const rems = result.remediations as Array<Record<string, unknown>>;
    expect(rems[0].spec_reference).toContain('Core Spec');
    expect(rems[0].short_term).toBeTruthy();
    expect(rems[0].long_term).toBeTruthy();

    const md = result.guide_markdown as string;
    expect(md).toContain('Remediation Guide');
    expect(md).toContain('F-001');
  });

  it('sorts findings by severity', async () => {
    const findingsPath = await writeFixture('mixed.json', {
      findings: [
        { finding_id: 'F-low', type: 'spec_deviation', severity: 'low', description: 'Minor' },
        { finding_id: 'F-crit', type: 'device_crash', severity: 'critical', description: 'Crash' },
      ],
    });

    const result = await generateRemediation.execute({ findings_path: findingsPath });
    const rems = result.remediations as Array<Record<string, unknown>>;
    expect(rems[0].severity).toBe('critical');
    expect(rems[1].severity).toBe('low');
  });
});
