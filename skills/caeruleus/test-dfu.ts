/**
 * test-dfu.ts — Nordic DFU security testing (Flow 3.7)
 *
 * Tests Nordic Secure DFU Service (UUID 0xFE59) for:
 * unsigned firmware acceptance, version downgrade, DFU mode triggering
 * without authentication, and init packet validation bypass.
 * Online: requires caeruleus-server.py
 */

import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';
import type { IBleClient } from './lib/types.js';
import { BleError } from './lib/errors.js';
import { BleMacAddressSchema, estimateTokens } from './lib/types.js';

// Nordic DFU UUIDs
const DFU_SERVICE_UUID = '0000fe59-0000-1000-8000-00805f9b34fb';
const DFU_CONTROL_POINT_UUID = '8ec90001-f315-4f60-9fb8-838830daea50';
const DFU_PACKET_UUID = '8ec90002-f315-4f60-9fb8-838830daea50';
const DFU_BUTTONLESS_UUID = '8ec90003-f315-4f60-9fb8-838830daea50';

// Nordic DFU opcodes
const DFU_OP = {
  CREATE: 0x01,
  SET_PRN: 0x02,
  CALCULATE_CHECKSUM: 0x03,
  EXECUTE: 0x04,
  SELECT: 0x06,
  RESPONSE: 0x60,
} as const;

// Object types
const DFU_OBJ = {
  COMMAND: 0x01, // Init packet
  DATA: 0x02,    // Firmware image
} as const;

export const testDfuParams = z.object({
  mac_address: BleMacAddressSchema.optional(),
  test_unsigned: z.boolean().default(true),
  test_downgrade: z.boolean().default(true),
  test_buttonless: z.boolean().default(true),
  dfu_service_uuid: z.string().default(DFU_SERVICE_UUID),
});
export type TestDfuInput = z.infer<typeof testDfuParams>;

export const testDfu = {
  name: 'caeruleus.test_dfu',
  description:
    'Test Nordic Secure DFU Service for unsigned firmware acceptance, version downgrade, unauthenticated DFU mode entry, and init packet validation bypass.',
  parameters: testDfuParams,

  async execute(
    input: TestDfuInput,
    client?: IBleClient,
  ): Promise<Record<string, unknown>> {
    const validated = testDfuParams.parse(input);
    const callFn = client
      ? (cmd: string, params: Record<string, unknown>) =>
          client.call({ command: cmd, params })
      : callBle;

    const findings: Array<Record<string, unknown>> = [];
    const testResults: Array<Record<string, unknown>> = [];

    // Step 1: Check if DFU service exists
    let dfuPresent = false;
    let dfuCharacteristics: string[] = [];
    try {
      const gattMap = (await callFn('get_gatt_map', {})) as Record<string, unknown>;
      const services = (gattMap.services || []) as Array<Record<string, unknown>>;
      for (const svc of services) {
        const svcUuid = (svc.uuid as string).toLowerCase();
        if (
          svcUuid.includes('fe59') ||
          svcUuid === validated.dfu_service_uuid.toLowerCase()
        ) {
          dfuPresent = true;
          const chars = (svc.characteristics || []) as Array<Record<string, unknown>>;
          dfuCharacteristics = chars.map((c) => c.uuid as string);
          break;
        }
      }
    } catch {
      // GATT map not available, try direct characteristic access
    }

    testResults.push({
      test: 'dfu_service_detection',
      dfu_present: dfuPresent,
      characteristics_found: dfuCharacteristics,
    });

    if (!dfuPresent) {
      const result = {
        schema_version: '1.0',
        dfu_present: false,
        dfu_type: 'nordic',
        test_results: testResults,
        findings,
        findings_count: 0,
        note: 'Nordic DFU Service (0xFE59) not detected on device',
        estimatedTokens: 0,
      };
      result.estimatedTokens = estimateTokens(result);
      return result;
    }

    findings.push({
      finding_id: 'F-atk-dfu-detected',
      type: 'dfu_service_exposed',
      severity: 'medium',
      description: 'Nordic DFU Service (0xFE59) is exposed and accessible',
      characteristics: dfuCharacteristics,
    });

    // Step 2: Test buttonless DFU entry (unauthenticated)
    if (validated.test_buttonless) {
      const buttonlessUuid = dfuCharacteristics.find((u) =>
        u.toLowerCase().includes('8ec90003'),
      ) || DFU_BUTTONLESS_UUID;

      try {
        // Subscribe for notifications on buttonless char
        await callFn('subscribe', { uuid: buttonlessUuid, duration: 5 });

        // Write buttonless DFU enter command (0x01)
        await callFn('write_characteristic', {
          uuid: buttonlessUuid,
          value_hex: '01',
        });

        testResults.push({
          test: 'buttonless_dfu_entry',
          accepted: true,
          uuid: buttonlessUuid,
        });

        findings.push({
          finding_id: 'F-atk-dfu-buttonless',
          type: 'dfu_unauthenticated_entry',
          severity: 'high',
          description:
            'Device entered DFU mode via buttonless characteristic without authentication',
          uuid: buttonlessUuid,
        });
      } catch (e) {
        const errMsg = (e as Error).message.toLowerCase();
        const rejected = errMsg.includes('auth') || errMsg.includes('encrypt') || errMsg.includes('denied');
        testResults.push({
          test: 'buttonless_dfu_entry',
          accepted: false,
          rejected_reason: rejected ? 'authentication_required' : 'error',
          error: (e as Error).message,
        });
      }
    }

    // Step 3: Test unsigned firmware acceptance
    if (validated.test_unsigned) {
      const controlUuid = dfuCharacteristics.find((u) =>
        u.toLowerCase().includes('8ec90001'),
      ) || DFU_CONTROL_POINT_UUID;

      const packetUuid = dfuCharacteristics.find((u) =>
        u.toLowerCase().includes('8ec90002'),
      ) || DFU_PACKET_UUID;

      try {
        // Subscribe for notifications on control point
        await callFn('subscribe', { uuid: controlUuid, duration: 10 });

        // SELECT command object (init packet type)
        const selectCmd = Buffer.from([DFU_OP.SELECT, DFU_OBJ.COMMAND]).toString('hex');
        const selectResult = (await callFn('write_characteristic', {
          uuid: controlUuid,
          value_hex: selectCmd,
        })) as Record<string, unknown>;

        testResults.push({
          test: 'select_command_object',
          accepted: true,
          result: selectResult,
        });

        // CREATE a small init packet (crafted minimal invalid init packet)
        const fakeInitSize = 32;
        const createCmd = Buffer.alloc(5);
        createCmd[0] = DFU_OP.CREATE;
        createCmd[1] = DFU_OBJ.COMMAND;
        createCmd.writeUInt16LE(fakeInitSize, 2);
        const createResult = (await callFn('write_characteristic', {
          uuid: controlUuid,
          value_hex: createCmd.toString('hex'),
        })) as Record<string, unknown>;

        testResults.push({
          test: 'create_command_object',
          accepted: true,
          size: fakeInitSize,
          result: createResult,
        });

        // Write a fake unsigned init packet to the packet characteristic
        const fakeInit = 'FF'.repeat(fakeInitSize);
        await callFn('write_no_response', {
          uuid: packetUuid,
          value_hex: fakeInit,
        });

        // Try to EXECUTE (this validates the init packet)
        const executeCmd = Buffer.from([DFU_OP.EXECUTE]).toString('hex');
        try {
          await callFn('write_characteristic', {
            uuid: controlUuid,
            value_hex: executeCmd,
          });

          // If execute succeeds, unsigned firmware was accepted
          testResults.push({
            test: 'unsigned_init_packet',
            accepted: true,
          });

          findings.push({
            finding_id: 'F-atk-dfu-unsigned',
            type: 'dfu_unsigned_firmware',
            severity: 'critical',
            description:
              'Device accepted unsigned/invalid init packet — firmware signing may not be enforced',
          });
        } catch (e) {
          // Expected: device should reject unsigned init packet
          testResults.push({
            test: 'unsigned_init_packet',
            accepted: false,
            rejection: (e as Error).message,
          });
        }
      } catch (e) {
        testResults.push({
          test: 'unsigned_firmware_test',
          accepted: false,
          error: (e as Error).message,
          note: 'Could not access DFU control point',
        });
      }
    }

    // Step 4: Test version downgrade
    if (validated.test_downgrade) {
      const controlUuid = dfuCharacteristics.find((u) =>
        u.toLowerCase().includes('8ec90001'),
      ) || DFU_CONTROL_POINT_UUID;

      try {
        // SELECT data object to read current firmware info
        const selectData = Buffer.from([DFU_OP.SELECT, DFU_OBJ.DATA]).toString('hex');
        const dataInfo = (await callFn('write_characteristic', {
          uuid: controlUuid,
          value_hex: selectData,
        })) as Record<string, unknown>;

        testResults.push({
          test: 'select_data_object',
          result: dataInfo,
          note: 'Firmware version info retrieved (if available in response notification)',
        });

        // Note: Actual downgrade test would require a valid signed older firmware
        // image. We can only detect if the SELECT command succeeds and report
        // that version checking should be verified manually.
        findings.push({
          finding_id: 'F-atk-dfu-downgrade-check',
          type: 'dfu_downgrade_check_needed',
          severity: 'informational',
          description:
            'DFU data object is accessible. Manual verification needed: test if device accepts signed firmware with older version number.',
        });
      } catch (e) {
        testResults.push({
          test: 'version_downgrade',
          error: (e as Error).message,
        });
      }
    }

    const result = {
      schema_version: '1.0',
      dfu_present: true,
      dfu_type: 'nordic',
      dfu_service_uuid: validated.dfu_service_uuid,
      characteristics_found: dfuCharacteristics,
      test_results: testResults,
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
  testDfu
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      const err = e as BleError;
      console.error(JSON.stringify({ error: err.message, code: err.code }, null, 2));
      process.exit(1);
    });
}
