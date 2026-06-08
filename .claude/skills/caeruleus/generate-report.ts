/**
 * generate-report.ts — Engagement summary report (Flow 4.6)
 *
 * Produces structured engagement summary: scope, methodology, findings by severity,
 * attack chain narratives, remediation roadmap.
 * Offline: reads all upstream artifacts from engagement directory.
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const generateReportParams = z.object({
  engagement_dir: z.string(),
  operator_name: z.string().optional(),
});
export type GenerateReportInput = z.infer<typeof generateReportParams>;

export const generateReport = {
  name: 'caeruleus.generate_report',
  description:
    'Generate a structured BLE security engagement report from all upstream artifacts.',
  parameters: generateReportParams,

  async execute(input: GenerateReportInput): Promise<Record<string, unknown>> {
    const validated = generateReportParams.parse(input);
    const engDir = validated.engagement_dir;

    // Load engagement config
    let config: Record<string, unknown> = {};
    try {
      const configRaw = await readFile(join(engDir, 'config', 'engagement.json'), 'utf-8');
      config = JSON.parse(configRaw);
    } catch {
      config = { engagement_id: 'unknown', target: { device_name: 'Unknown Device' } };
    }

    // Load correlated findings
    let correlatedFindings: Record<string, unknown> = {};
    try {
      const findingsRaw = await readFile(join(engDir, 'reports', 'correlated-findings.json'), 'utf-8');
      correlatedFindings = JSON.parse(findingsRaw);
    } catch {
      correlatedFindings = { findings: [], by_severity: {}, attack_chains: [] };
    }

    // Load device fingerprint
    let fingerprint: Record<string, unknown> = {};
    try {
      const fpRaw = await readFile(join(engDir, 'recon', 'device-fingerprint.json'), 'utf-8');
      fingerprint = JSON.parse(fpRaw);
    } catch {
      fingerprint = {};
    }

    // Load security posture
    let posture: Record<string, unknown> = {};
    try {
      const postureRaw = await readFile(join(engDir, 'analysis', 'security-posture.json'), 'utf-8');
      posture = JSON.parse(postureRaw);
    } catch {
      posture = {};
    }

    const target = (config.target || {}) as Record<string, unknown>;
    const bySeverity = (correlatedFindings.by_severity || {}) as Record<string, number>;
    const findings = (correlatedFindings.findings || []) as Array<Record<string, unknown>>;
    const chains = (correlatedFindings.attack_chains || []) as Array<Record<string, unknown>>;

    const now = new Date().toISOString();

    // Generate markdown report
    const reportLines = [
      `# BLE Security Assessment Report`,
      ``,
      `**Engagement:** ${config.engagement_id || 'N/A'}`,
      `**Target Device:** ${target.device_name || 'Unknown'}`,
      `**MAC Address:** ${target.mac_address || 'N/A'}`,
      `**Date:** ${now.split('T')[0]}`,
      `**Operator:** ${validated.operator_name || (config.operator as Record<string, unknown>)?.name || 'N/A'}`,
      ``,
      `---`,
      ``,
      `## Executive Summary`,
      ``,
      `Overall risk: **${(posture.overall_risk as string || 'undetermined').toUpperCase()}**`,
      ``,
      `| Severity | Count |`,
      `|----------|-------|`,
      `| Critical | ${bySeverity.critical || 0} |`,
      `| High | ${bySeverity.high || 0} |`,
      `| Medium | ${bySeverity.medium || 0} |`,
      `| Low | ${bySeverity.low || 0} |`,
      `| Informational | ${bySeverity.informational || 0} |`,
      `| **Total** | **${findings.length}** |`,
      ``,
      `Attack chains identified: **${chains.length}**`,
      ``,
      `---`,
      ``,
      `## Device Profile`,
      ``,
      `- **Chipset:** ${(fingerprint.chipset as Record<string, unknown>)?.chipset_family || 'Unknown'}`,
      `- **Manufacturer:** ${(fingerprint.chipset as Record<string, unknown>)?.company || 'Unknown'}`,
      `- **Known CVEs:** ${(fingerprint.known_cve_count as number) || 0}`,
      `- **DFU Service:** ${(fingerprint.dfu_detected as Record<string, unknown>)?.present ? 'Present' : 'Not detected'}`,
      ``,
      `---`,
      ``,
      `## Findings`,
      ``,
    ];

    // Group findings by severity
    const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
    for (const sev of severityOrder) {
      const sevFindings = findings.filter((f) => f.severity === sev);
      if (sevFindings.length === 0) continue;

      reportLines.push(`### ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${sevFindings.length})`);
      reportLines.push('');

      for (const f of sevFindings) {
        reportLines.push(`#### ${f.finding_id}: ${f.description}`);
        reportLines.push('');
        reportLines.push(`- **Type:** ${f.type}`);
        if (f.uuid) reportLines.push(`- **Characteristic:** ${f.uuid}`);
        reportLines.push('');
      }
    }

    // Attack chains section
    if (chains.length > 0) {
      reportLines.push('---');
      reportLines.push('');
      reportLines.push('## Attack Chains');
      reportLines.push('');
      for (const chain of chains) {
        reportLines.push(`### ${chain.chain_id}: ${chain.description}`);
        reportLines.push('');
        reportLines.push(`- **Severity:** ${chain.severity}`);
        reportLines.push(`- **Findings:** ${(chain.findings as string[]).join(' -> ')}`);
        reportLines.push('');
      }
    }

    reportLines.push('---');
    reportLines.push('');
    reportLines.push('## Methodology');
    reportLines.push('');
    reportLines.push('Assessment performed using Caeruleus BLE security testing framework:');
    reportLines.push('- Phase 1: Device discovery, GATT enumeration, permission probing, fingerprinting');
    reportLines.push('- Phase 2: Pairing analysis, encryption assessment, notification traffic capture, GATT audit');
    reportLines.push('- Phase 3: Characteristic fuzzing, write-without-response abuse, auth bypass, replay testing');
    reportLines.push('- Phase 4: Finding correlation, CVE mapping, evidence assembly, report generation');
    reportLines.push('');
    reportLines.push('---');
    reportLines.push('');
    reportLines.push(`*Generated by Caeruleus BLE Security Framework on ${now}*`);

    const reportMarkdown = reportLines.join('\n');

    const result = {
      report_markdown: reportMarkdown,
      report_length: reportMarkdown.length,
      findings_count: findings.length,
      attack_chains_count: chains.length,
      overall_risk: posture.overall_risk || 'undetermined',
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  generateReport
    .execute(input)
    .then((r) => {
      // Write markdown to stdout for easy piping
      console.log((r as Record<string, unknown>).report_markdown);
    })
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
