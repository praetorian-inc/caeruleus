/**
 * generate-remediation.ts — Remediation guidance generation (Flow 4.5)
 *
 * For each finding: generates remediation recommendations referencing
 * Bluetooth SIG best practices, maps to relevant BLE spec sections.
 * Offline: reads correlated findings, no server needed.
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const generateRemediationParams = z.object({
  findings_path: z.string(),
  cve_mapping_path: z.string().optional(),
});
export type GenerateRemediationInput = z.infer<typeof generateRemediationParams>;

// BLE spec reference lookup by finding type
const REMEDIATION_TEMPLATES: Record<
  string,
  {
    short_term: string;
    long_term: string;
    spec_reference: string;
  }
> = {
  pairing_not_enforced: {
    short_term: 'Enable mandatory pairing for all sensitive characteristics',
    long_term: 'Implement Secure Connections Only mode (BLE 4.2+) with MITM protection',
    spec_reference: 'Core Spec v5.3, Vol 3, Part H, Section 2.3.5 (Pairing Methods)',
  },
  legacy_fallback: {
    short_term: 'Disable legacy pairing fallback on the device',
    long_term: 'Set Secure Connections Only flag and reject Legacy Pairing requests',
    spec_reference: 'Core Spec v5.3, Vol 3, Part H, Section 2.3.5.6.2',
  },
  information_disclosure: {
    short_term: 'Require encryption for Device Information service characteristics',
    long_term: 'Minimize broadcast data; remove serial numbers and firmware versions from advertisements',
    spec_reference: 'Core Spec v5.3, Vol 3, Part C, Section 12.1 (Device Information Service)',
  },
  unauthenticated_write: {
    short_term: 'Set write permissions to require encryption or authentication',
    long_term: 'Implement application-layer authentication with challenge-response',
    spec_reference: 'Core Spec v5.3, Vol 3, Part F, Section 3.2.5 (Characteristic Properties)',
  },
  custom_unauthenticated_write: {
    short_term: 'Require at minimum encryption for all writable custom characteristics',
    long_term: 'Implement per-characteristic access control with application-layer tokens',
    spec_reference: 'Core Spec v5.3, Vol 3, Part F, Section 3.2.5',
  },
  custom_unauthenticated_read: {
    short_term: 'Review if characteristic contains sensitive data; add encryption if so',
    long_term: 'Classify all custom characteristics by data sensitivity; apply appropriate access controls',
    spec_reference: 'Core Spec v5.3, Vol 3, Part C, Section 10.3 (Privacy)',
  },
  device_crash: {
    short_term: 'Add input validation and length checks on all writable characteristics',
    long_term: 'Implement fuzz testing in CI/CD pipeline; add watchdog timer for crash recovery',
    spec_reference: 'Core Spec v5.3, Vol 3, Part F, Section 3.4.5 (Write Request)',
  },
  missing_replay_protection: {
    short_term: 'Add sequence numbers or timestamps to command protocol',
    long_term: 'Implement challenge-response with nonces for all state-changing commands',
    spec_reference: 'Core Spec v5.3, Vol 3, Part H, Section 2.4.6 (Encryption Key Refresh)',
  },
  unencrypted_traffic: {
    short_term: 'Enable link-layer encryption for all connections',
    long_term: 'Enforce encryption at connection establishment; reject unencrypted connections',
    spec_reference: 'Core Spec v5.3, Vol 6, Part B, Section 5.1.3 (Encryption Start Procedure)',
  },
  wwr_buffer_overflow: {
    short_term: 'Limit accepted write-without-response payload size to MTU-3',
    long_term: 'Implement strict input validation with size bounds on all write handlers',
    spec_reference: 'Core Spec v5.3, Vol 3, Part F, Section 3.4.5.3 (Write Without Response)',
  },
  wwr_resource_exhaustion: {
    short_term: 'Implement rate limiting on write-without-response operations',
    long_term: 'Add per-client rate limiting and connection parameter bounds',
    spec_reference: 'Core Spec v5.3, Vol 6, Part B, Section 4.5.1 (Connection Parameters)',
  },
  spec_deviation: {
    short_term: 'Add missing required characteristics per Bluetooth SIG profile specification',
    long_term: 'Validate GATT profile against SIG qualification test suite',
    spec_reference: 'Bluetooth SIG GATT Profile Specifications',
  },
};

const DEFAULT_REMEDIATION = {
  short_term: 'Review finding and assess impact; apply vendor-recommended mitigation',
  long_term: 'Conduct thorough security review of affected component; follow BLE SIG best practices',
  spec_reference: 'Core Spec v5.3, Security Overview',
};

export const generateRemediation = {
  name: 'caeruleus.generate_remediation',
  description:
    'Generate remediation recommendations for each finding with BLE spec references and best practices.',
  parameters: generateRemediationParams,

  async execute(input: GenerateRemediationInput): Promise<Record<string, unknown>> {
    const validated = generateRemediationParams.parse(input);

    const findingsRaw = await readFile(validated.findings_path, 'utf-8');
    const findingsData = JSON.parse(findingsRaw);
    const findings = (findingsData.findings || []) as Array<Record<string, unknown>>;

    // Load CVE mapping if available
    let cveMap: Map<string, Record<string, unknown>> = new Map();
    if (validated.cve_mapping_path) {
      try {
        const cveRaw = await readFile(validated.cve_mapping_path, 'utf-8');
        const cveData = JSON.parse(cveRaw);
        for (const cve of (cveData.matched_cves || []) as Array<Record<string, unknown>>) {
          cveMap.set(cve.cve_id as string, cve);
        }
      } catch {
        // CVE mapping optional
      }
    }

    const remediations: Array<Record<string, unknown>> = [];
    const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];

    // Sort findings by severity
    const sortedFindings = [...findings].sort((a, b) =>
      severityOrder.indexOf(a.severity as string) - severityOrder.indexOf(b.severity as string),
    );

    for (const finding of sortedFindings) {
      const findingType = finding.type as string;
      const template = REMEDIATION_TEMPLATES[findingType] || DEFAULT_REMEDIATION;

      const remediation: Record<string, unknown> = {
        finding_id: finding.finding_id,
        finding_type: findingType,
        severity: finding.severity,
        description: finding.description,
        uuid: finding.uuid || finding.characteristic,
        short_term: template.short_term,
        long_term: template.long_term,
        spec_reference: template.spec_reference,
        priority: severityOrder.indexOf(finding.severity as string) + 1,
      };

      // Add CVE-specific remediation if available
      const cveRefs = (finding.cve_references || []) as string[];
      if (cveRefs.length > 0) {
        remediation.cve_remediations = cveRefs
          .map((id) => cveMap.get(id))
          .filter(Boolean)
          .map((cve) => ({
            cve_id: cve!.cve_id,
            remediation: cve!.remediation,
          }));
      }

      remediations.push(remediation);
    }

    // Generate markdown guide
    const lines: string[] = [
      '# BLE Security Remediation Guide',
      '',
      `Total findings requiring remediation: **${remediations.length}**`,
      '',
      '---',
      '',
    ];

    let currentSeverity = '';
    for (const rem of remediations) {
      if (rem.severity !== currentSeverity) {
        currentSeverity = rem.severity as string;
        lines.push(`## ${(currentSeverity as string).charAt(0).toUpperCase() + (currentSeverity as string).slice(1)} Priority`);
        lines.push('');
      }

      lines.push(`### ${rem.finding_id}: ${rem.finding_type}`);
      lines.push('');
      lines.push(`**Finding:** ${rem.description}`);
      if (rem.uuid) lines.push(`**Affected:** \`${rem.uuid}\``);
      lines.push('');
      lines.push(`**Short-term fix:** ${rem.short_term}`);
      lines.push('');
      lines.push(`**Long-term fix:** ${rem.long_term}`);
      lines.push('');
      lines.push(`**BLE Spec Reference:** ${rem.spec_reference}`);
      lines.push('');
    }

    lines.push('---');
    lines.push('');
    lines.push('*Generated by Caeruleus BLE Security Framework*');

    const guideMarkdown = lines.join('\n');

    const result = {
      schema_version: '1.0',
      total_remediations: remediations.length,
      by_priority: {
        critical: remediations.filter((r) => r.severity === 'critical').length,
        high: remediations.filter((r) => r.severity === 'high').length,
        medium: remediations.filter((r) => r.severity === 'medium').length,
        low: remediations.filter((r) => r.severity === 'low').length,
        informational: remediations.filter((r) => r.severity === 'informational').length,
      },
      remediations,
      guide_markdown: guideMarkdown,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  generateRemediation
    .execute(input)
    .then((r) => console.log((r as Record<string, unknown>).guide_markdown))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
