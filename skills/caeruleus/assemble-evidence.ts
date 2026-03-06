/**
 * assemble-evidence.ts — Evidence package assembly (Flow 4.4)
 *
 * Assembles pcaps, GATT dumps, fuzz logs, and crash dumps into a
 * structured evidence package with chain-of-custody metadata.
 * Offline: reads all artifacts from engagement directory.
 */

import { z } from 'zod';
import { readFile, readdir, stat, writeFile, mkdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const assembleEvidenceParams = z.object({
  engagement_dir: z.string(),
  output_dir: z.string().optional(),
});
export type AssembleEvidenceInput = z.infer<typeof assembleEvidenceParams>;

interface EvidenceItem {
  path: string;
  relative_path: string;
  type: string;
  size_bytes: number;
  category: string;
  phase: string;
}

async function collectFiles(
  dir: string,
  baseDir: string,
  category: string,
  phase: string,
): Promise<EvidenceItem[]> {
  const items: EvidenceItem[] = [];
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        items.push(...await collectFiles(fullPath, baseDir, category, phase));
      } else {
        const fileStat = await stat(fullPath);
        const ext = entry.name.split('.').pop() || '';
        let type = 'unknown';
        if (ext === 'json') type = 'data';
        else if (ext === 'pcap' || ext === 'pcapng') type = 'capture';
        else if (ext === 'py') type = 'script';
        else if (ext === 'md') type = 'report';
        else if (ext === 'svg' || ext === 'png') type = 'visualization';
        else if (ext === 'zip') type = 'archive';
        else if (ext === 'log' || ext === 'txt') type = 'log';

        items.push({
          path: fullPath,
          relative_path: relative(baseDir, fullPath),
          type,
          size_bytes: fileStat.size,
          category,
          phase,
        });
      }
    }
  } catch {
    // Directory may not exist
  }
  return items;
}

export const assembleEvidence = {
  name: 'caeruleus.assemble_evidence',
  description:
    'Assemble all engagement artifacts into a structured evidence package with chain-of-custody metadata.',
  parameters: assembleEvidenceParams,

  async execute(input: AssembleEvidenceInput): Promise<Record<string, unknown>> {
    const validated = assembleEvidenceParams.parse(input);
    const engDir = validated.engagement_dir;
    const outDir = validated.output_dir || join(engDir, 'reports', 'evidence');
    await mkdir(outDir, { recursive: true });

    // Collect all artifacts
    const allItems: EvidenceItem[] = [];

    const phaseDirs: Array<{ dir: string; category: string; phase: string }> = [
      { dir: join(engDir, 'config'), category: 'configuration', phase: 'setup' },
      { dir: join(engDir, 'recon'), category: 'reconnaissance', phase: '1' },
      { dir: join(engDir, 'analysis'), category: 'analysis', phase: '2' },
      { dir: join(engDir, 'attacks'), category: 'attack_results', phase: '3' },
      { dir: join(engDir, 'reports'), category: 'reports', phase: '4' },
    ];

    for (const { dir, category, phase } of phaseDirs) {
      allItems.push(...await collectFiles(dir, engDir, category, phase));
    }

    // Check for operator log
    try {
      const opLogPath = join(engDir, 'operator-log.json');
      const opLogStat = await stat(opLogPath);
      allItems.push({
        path: opLogPath,
        relative_path: 'operator-log.json',
        type: 'data',
        size_bytes: opLogStat.size,
        category: 'operator_interaction',
        phase: 'all',
      });
    } catch {
      // No operator log
    }

    // Load engagement config for metadata
    let config: Record<string, unknown> = {};
    try {
      const configRaw = await readFile(join(engDir, 'config', 'engagement.json'), 'utf-8');
      config = JSON.parse(configRaw);
    } catch {
      config = { engagement_id: 'unknown' };
    }

    // Build manifest
    const manifest = {
      schema_version: '1.0',
      engagement_id: config.engagement_id,
      assembly_timestamp: new Date().toISOString(),
      engagement_dir: engDir,
      total_artifacts: allItems.length,
      total_size_bytes: allItems.reduce((sum, item) => sum + item.size_bytes, 0),
      by_phase: {
        setup: allItems.filter((i) => i.phase === 'setup').length,
        phase_1: allItems.filter((i) => i.phase === '1').length,
        phase_2: allItems.filter((i) => i.phase === '2').length,
        phase_3: allItems.filter((i) => i.phase === '3').length,
        phase_4: allItems.filter((i) => i.phase === '4').length,
      },
      by_type: {
        data: allItems.filter((i) => i.type === 'data').length,
        capture: allItems.filter((i) => i.type === 'capture').length,
        script: allItems.filter((i) => i.type === 'script').length,
        report: allItems.filter((i) => i.type === 'report').length,
        visualization: allItems.filter((i) => i.type === 'visualization').length,
        log: allItems.filter((i) => i.type === 'log').length,
      },
      artifacts: allItems.map((item) => ({
        relative_path: item.relative_path,
        type: item.type,
        size_bytes: item.size_bytes,
        category: item.category,
        phase: item.phase,
      })),
    };

    // Write manifest
    const manifestPath = join(outDir, 'evidence-manifest.json');
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');

    const result = {
      schema_version: '1.0',
      manifest_path: manifestPath,
      output_dir: outDir,
      total_artifacts: allItems.length,
      total_size_bytes: manifest.total_size_bytes,
      by_phase: manifest.by_phase,
      by_type: manifest.by_type,
      engagement_id: config.engagement_id,
      note: 'Evidence manifest written. Use system tar/zip to create final archive.',
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  assembleEvidence
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
