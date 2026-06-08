/**
 * correlate-findings.ts — Finding correlation & deduplication (Flow 4.2)
 *
 * Aggregates findings across all agents, deduplicates, correlates related issues
 * into attack chains, assigns severity ratings.
 * Offline: reads all findings JSONs from engagement directory.
 */

import { z } from 'zod';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const correlateFindingsParams = z.object({
  engagement_dir: z.string(),
});
export type CorrelateFindingsInput = z.infer<typeof correlateFindingsParams>;

interface RawFinding {
  finding_id?: string;
  type: string;
  severity: string;
  uuid?: string;
  characteristic?: string;
  description: string;
  [key: string]: unknown;
}

export const correlateFindings = {
  name: 'caeruleus.correlate_findings',
  description:
    'Aggregate and correlate BLE security findings from all engagement phases. Deduplicates, builds attack chains, assigns severity.',
  parameters: correlateFindingsParams,

  async execute(input: CorrelateFindingsInput): Promise<Record<string, unknown>> {
    const validated = correlateFindingsParams.parse(input);
    const engDir = validated.engagement_dir;

    const allFindings: RawFinding[] = [];
    const sources: string[] = [];

    // Collect findings from all phase directories
    const phaseDirs = ['recon', 'analysis', 'attacks'];
    for (const phase of phaseDirs) {
      const phaseDir = join(engDir, phase);
      try {
        const files = await readdir(phaseDir);
        for (const file of files) {
          if (!file.endsWith('.json')) continue;
          try {
            const raw = await readFile(join(phaseDir, file), 'utf-8');
            const data = JSON.parse(raw);
            const findings = data.findings || [];
            if (findings.length > 0) {
              allFindings.push(...findings);
              sources.push(`${phase}/${file}`);
            }
          } catch {
            // Skip unparseable files
          }
        }
      } catch {
        // Phase dir doesn't exist yet
      }
    }

    // Deduplicate by type + uuid/characteristic
    const deduped: Map<string, RawFinding> = new Map();
    for (const f of allFindings) {
      const key = `${f.type}:${f.uuid || f.characteristic || 'global'}`;
      if (!deduped.has(key)) {
        deduped.set(key, f);
      } else {
        // Merge: keep higher severity
        const existing = deduped.get(key)!;
        const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
        if (severityOrder.indexOf(f.severity) < severityOrder.indexOf(existing.severity)) {
          deduped.set(key, { ...existing, ...f });
        }
      }
    }

    const dedupedFindings = Array.from(deduped.values());

    // Assign finding IDs if missing
    let findingCounter = 1;
    for (const f of dedupedFindings) {
      if (!f.finding_id) {
        f.finding_id = `F-corr-${String(findingCounter++).padStart(3, '0')}`;
      }
    }

    // Build attack chains (group related findings by UUID)
    const chainMap: Map<string, RawFinding[]> = new Map();
    for (const f of dedupedFindings) {
      const target = f.uuid || f.characteristic || 'global';
      if (!chainMap.has(target)) chainMap.set(target, []);
      chainMap.get(target)!.push(f);
    }

    const attackChains: Array<Record<string, unknown>> = [];
    let chainId = 1;
    for (const [target, findings] of chainMap) {
      if (findings.length >= 2) {
        attackChains.push({
          chain_id: `AC-${String(chainId++).padStart(3, '0')}`,
          target,
          findings: findings.map((f) => f.finding_id),
          severity: findings.reduce(
            (worst, f) => {
              const order = ['critical', 'high', 'medium', 'low', 'informational'];
              return order.indexOf(f.severity) < order.indexOf(worst) ? f.severity : worst;
            },
            'informational' as string,
          ),
          description: `Attack chain on ${target}: ${findings.map((f) => f.type).join(' -> ')}`,
        });
      }
    }

    // Count by severity
    const bySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };
    for (const f of dedupedFindings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    }

    const result = {
      schema_version: '1.0',
      total_raw_findings: allFindings.length,
      deduplicated_findings: dedupedFindings.length,
      duplicates_removed: allFindings.length - dedupedFindings.length,
      by_severity: bySeverity,
      attack_chains: attackChains,
      attack_chain_count: attackChains.length,
      findings: dedupedFindings,
      sources,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  correlateFindings
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
