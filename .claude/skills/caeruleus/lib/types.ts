import { z } from 'zod';

// --- IPC Protocol Types (generic Proteus wire protocol) ---

export interface CaeruleusRequest {
  id: number;
  command: string;
  params: Record<string, unknown>;
}

export interface CaeruleusResponseOk {
  id: number;
  status: 'ok';
  result: Record<string, unknown>;
}

export interface CaeruleusResponseError {
  id: number;
  status: 'error';
  error: {
    code: string;
    message: string;
    recoverable: boolean;
    suggestion?: string;
  };
}

export type CaeruleusResponse = CaeruleusResponseOk | CaeruleusResponseError;

export interface CaeruleusCallParams {
  command: string;
  params?: Record<string, unknown>;
}

export interface IBleClient {
  call(params: CaeruleusCallParams): Promise<unknown>;
  ping(): Promise<{ pong: boolean; connected: boolean }>;
  shutdown(): Promise<void>;
}

// --- BLE Domain Types ---

/**
 * Accepts BLE ATT handles as either a decimal number (78) or a hex string ("0x004e").
 * GATT enumeration returns hex strings, so agents naturally pass those downstream.
 * Coerces to a plain number for server consumption.
 */
export const BleHandleSchema = z
  .union([z.number().int(), z.string()])
  .transform((val, ctx) => {
    if (typeof val === 'number') return val;
    const s = val.trim();
    const n =
      s.startsWith('0x') || s.startsWith('0X')
        ? parseInt(s, 16)
        : parseInt(s, 10);
    if (isNaN(n) || !Number.isInteger(n)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `Invalid handle: ${val}`,
      });
      return z.NEVER;
    }
    return n;
  });

export const BleMacAddressSchema = z
  .string()
  .regex(
    /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$/,
    'Invalid MAC address or CoreBluetooth UUID',
  );

export const BleMacTypeSchema = z.enum(['public', 'random']);

// Scan parameters
export const BleScanParamsSchema = z.object({
  duration: z.number().min(1).max(300).default(10),
  adapter: z.string().default('hci0'),
  active: z.boolean().default(false),
});
export type BleScanParams = z.infer<typeof BleScanParamsSchema>;

// Connect parameters
export const BleConnectParamsSchema = z.object({
  mac_address: BleMacAddressSchema,
  mac_type: BleMacTypeSchema.default('public'),
  adapter: z.string().default('hci0'),
  timeout: z.number().min(1).max(60).default(30),
});
export type BleConnectParams = z.infer<typeof BleConnectParamsSchema>;

// Read characteristic parameters
export const BleReadCharParamsSchema = z.object({
  uuid: z.string().min(4),
  handle: z.string().optional(),
});
export type BleReadCharParams = z.infer<typeof BleReadCharParamsSchema>;

// Write characteristic parameters
export const BleWriteCharParamsSchema = z.object({
  uuid: z.string().min(4),
  handle: z.string().optional(),
  value_hex: z.string().regex(/^[0-9a-fA-F]*$/, 'Value must be hex string'),
  response: z.boolean().default(true),
});
export type BleWriteCharParams = z.infer<typeof BleWriteCharParamsSchema>;

// Subscribe parameters
export const BleSubscribeParamsSchema = z.object({
  uuid: z.string().min(4),
  handle: z.string().optional(),
  duration: z.number().min(1).max(3600).default(30),
});
export type BleSubscribeParams = z.infer<typeof BleSubscribeParamsSchema>;

// Probe permissions parameters
export const BleProbePermissionsParamsSchema = z.object({
  timeout_per_char: z.number().min(0.5).max(10).default(2),
});
export type BleProbePermissionsParams = z.infer<typeof BleProbePermissionsParamsSchema>;

// Pair parameters
export const BlePairParamsSchema = z.object({
  mac_address: BleMacAddressSchema.optional(),
  method: z.enum(['just_works', 'passkey', 'numeric_comparison', 'oob']).optional(),
});
export type BlePairParams = z.infer<typeof BlePairParamsSchema>;

// Fuzz parameters
export const BleFuzzCharParamsSchema = z.object({
  uuid: z.string().min(4),
  handle: z.string().optional(),
  strategy: z.enum(['random', 'boundary', 'type_aware', 'overflow']).default('type_aware'),
  iterations: z.number().min(1).max(10000).default(100),
  delay_ms: z.number().min(0).max(5000).default(50),
});
export type BleFuzzCharParams = z.infer<typeof BleFuzzCharParamsSchema>;

// --- Device & GATT Schemas (output validation) ---

export const BleDiscoveredDeviceSchema = z.object({
  mac_address: z.string(),
  mac_type: BleMacTypeSchema,
  device_name: z.string().nullable(),
  rssi_dbm: z.number(),
  tx_power_dbm: z.number().nullable(),
  connectable: z.boolean(),
  service_uuids: z.array(z.string()),
  manufacturer_data: z.record(z.string()).optional(),
  flags: z.array(z.string()).optional(),
  advertisement_count: z.number().optional(),
  first_seen: z.string(),
  last_seen: z.string(),
  is_target: z.boolean().default(false),
});
export type BleDiscoveredDevice = z.infer<typeof BleDiscoveredDeviceSchema>;

export const BleGattDescriptorSchema = z.object({
  uuid: z.string(),
  name: z.string().nullable(),
  handle: z.string(),
  value_hex: z.string().nullable(),
});

export const BleCharacteristicPropertiesSchema = z.object({
  broadcast: z.boolean(),
  read: z.boolean(),
  write_no_response: z.boolean(),
  write: z.boolean(),
  notify: z.boolean(),
  indicate: z.boolean(),
  authenticated_signed_writes: z.boolean(),
  extended_properties: z.boolean(),
});

export const BleGattCharacteristicSchema = z.object({
  uuid: z.string(),
  uuid_short: z.string().nullable(),
  name: z.string().nullable(),
  handle: z.string(),
  value_handle: z.string(),
  properties: BleCharacteristicPropertiesSchema,
  security: z.object({
    read_requires: z.enum(['none', 'encryption', 'authentication']),
    write_requires: z.enum(['none', 'encryption', 'authentication']),
  }),
  value: z
    .object({
      raw_hex: z.string(),
      decoded: z.string().nullable(),
      encoding: z.string().nullable(),
    })
    .nullable(),
  descriptors: z.array(BleGattDescriptorSchema),
});
export type BleGattCharacteristic = z.infer<typeof BleGattCharacteristicSchema>;

export const BleGattServiceSchema = z.object({
  uuid: z.string(),
  uuid_short: z.string().nullable(),
  name: z.string().nullable(),
  type: z.enum(['standard', 'custom']),
  handle_start: z.string(),
  handle_end: z.string(),
  characteristics: z.array(BleGattCharacteristicSchema),
});
export type BleGattService = z.infer<typeof BleGattServiceSchema>;

export const BleGattMapSchema = z.object({
  schema_version: z.string().default('1.0'),
  device_mac: z.string(),
  connection_timestamp: z.string(),
  mtu: z.number(),
  services: z.array(BleGattServiceSchema),
  summary: z.object({
    total_services: z.number(),
    standard_services: z.number(),
    custom_services: z.number(),
    total_characteristics: z.number(),
    readable: z.number(),
    writable: z.number(),
    notifiable: z.number(),
    indicatable: z.number(),
  }),
});
export type BleGattMap = z.infer<typeof BleGattMapSchema>;

// --- Finding Schema ---

export const BleFindingSeverity = z.enum([
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]);

export const BleFindingCategory = z.enum([
  'authentication',
  'encryption',
  'information_disclosure',
  'injection',
  'denial_of_service',
  'firmware',
  'replay',
  'spoofing',
  'configuration',
]);

export const BleFindingSchema = z.object({
  finding_id: z.string(),
  source_flow: z.string(),
  source_agent: z.string(),
  timestamp: z.string(),
  severity: BleFindingSeverity,
  cvss_v3_score: z.number().min(0).max(10).optional(),
  cvss_v3_vector: z.string().optional(),
  title: z.string(),
  category: BleFindingCategory,
  affected_characteristic: z
    .object({
      service_uuid: z.string(),
      characteristic_uuid: z.string(),
      handle: z.string(),
      name: z.string().nullable(),
    })
    .optional(),
  description: z.string(),
  reproduction: z.object({
    prerequisites: z.array(z.string()),
    steps: z.array(z.string()),
    interaction_pattern: z.string(),
    operator_actions: z.array(z.string()),
  }),
  evidence: z.object({
    pcap_file: z.string().optional(),
    screenshots: z.array(z.string()),
    logs: z.array(z.string()),
    raw_request_hex: z.string().optional(),
    raw_response_hex: z.string().optional(),
    tool_used: z.string(),
    tool_command: z.string(),
  }),
  related_findings: z.array(z.string()),
  attack_chain: z
    .object({
      position: z.number(),
      chain_id: z.string(),
      chain_description: z.string(),
      next_finding: z.string().optional(),
    })
    .optional(),
  cve_references: z.array(z.string()),
  remediation: z.object({
    short_term: z.string(),
    long_term: z.string(),
    ble_spec_reference: z.string().optional(),
  }),
});
export type BleFinding = z.infer<typeof BleFindingSchema>;

// --- Security Posture Schema ---

export const BleSecurityPostureSchema = z.object({
  schema_version: z.string().default('1.0'),
  device_mac: z.string(),
  assessment_timestamp: z.string(),
  pairing: z.object({
    method: z.string(),
    enforced: z.boolean(),
    legacy_fallback: z.boolean(),
    mitm_protection: z.boolean(),
  }),
  encryption: z.object({
    link_layer_enforced: z.boolean(),
    min_key_size: z.number(),
    characteristics_unencrypted: z.array(z.string()),
    knob_susceptible: z.boolean(),
  }),
  authentication: z.object({
    app_layer_auth: z.boolean(),
    challenge_response: z.boolean(),
    token_based: z.boolean(),
  }),
  attack_surface_priority: z.array(
    z.object({
      characteristic_uuid: z.string(),
      handle: z.string(),
      risk: z.string(),
      rationale: z.string(),
      recommended_attacks: z.array(z.string()),
    }),
  ),
  dfu_detected: z
    .object({
      present: z.boolean(),
      type: z.string().optional(),
      service_uuid: z.string().optional(),
      secured: z.boolean().optional(),
    })
    .optional(),
  overall_risk: BleFindingSeverity,
  summary: z.string(),
});
export type BleSecurityPosture = z.infer<typeof BleSecurityPostureSchema>;

// --- Engagement Config Schema ---

export const BleEngagementConfigSchema = z.object({
  schema_version: z.string().default('1.0'),
  engagement_id: z.string(),
  target: z.object({
    device_name: z.string(),
    mac_address: BleMacAddressSchema,
    mac_type: BleMacTypeSchema,
    known_services: z.array(z.string()).default([]),
    companion_app: z
      .object({
        platform: z.enum(['android', 'ios', 'both']),
        package: z.string(),
      })
      .optional(),
  }),
  scope: z.object({
    phases: z.array(z.number().min(1).max(4)).default([1, 2, 3, 4]),
    excluded_flows: z.array(z.string()).default([]),
    hardware_available: z.array(z.string()).default([]),
    adapter: z.string().default('hci0'),
    time_budget_minutes: z.number().optional(),
  }),
  operator: z.object({
    name: z.string(),
    engagement_ref: z.string(),
  }),
});
export type BleEngagementConfig = z.infer<typeof BleEngagementConfigSchema>;

// --- Operator Interaction Log ---

export const BleOperatorInteractionSchema = z.object({
  interaction_id: z.string(),
  timestamp: z.string(),
  requesting_agent: z.string(),
  requesting_flow: z.string(),
  pattern: z.enum([
    'fully_automated',
    'prompt_and_wait',
    'prepare_execute_capture',
    'async_choreography',
  ]),
  phase: z.string(),
  request: z.string(),
  operator_response: z.string(),
  response_timestamp: z.string().optional(),
  notes: z.string().default(''),
});
export type BleOperatorInteraction = z.infer<typeof BleOperatorInteractionSchema>;

// --- Token estimation ---

export function estimateTokens(data: unknown): number {
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  return Math.ceil(str.length / 3.2);
}
