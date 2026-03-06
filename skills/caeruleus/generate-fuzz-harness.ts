/**
 * generate-fuzz-harness.ts — Fuzzing harness generation (Flow 3.1)
 *
 * Generates type-aware fuzz input scripts for each writable characteristic.
 * Produces reusable Python fuzzing harnesses from GATT map.
 * Offline: reads gatt-map.json, no server needed.
 */

import { z } from 'zod';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { estimateTokens } from './lib/types.js';

export const generateFuzzHarnessParams = z.object({
  gatt_map_path: z.string(),
  output_dir: z.string(),
  strategies: z
    .array(z.enum(['random', 'boundary', 'type_aware', 'overflow']))
    .default(['type_aware', 'boundary', 'overflow']),
  iterations: z.number().min(1).max(10000).default(100),
});
export type GenerateFuzzHarnessInput = z.infer<typeof generateFuzzHarnessParams>;

function generateHarnessScript(
  mac: string,
  uuid: string,
  charName: string | null,
  strategies: string[],
  iterations: number,
): string {
  const safeName = (charName || uuid).replace(/[^a-zA-Z0-9]/g, '_').toLowerCase();

  return `#!/usr/bin/env python3
"""
Auto-generated BLE fuzz harness for characteristic ${uuid}
Target: ${mac}
Name: ${charName || 'Unknown'}
Strategies: ${strategies.join(', ')}
Iterations: ${iterations}

Usage: python3 fuzz-${safeName}.py
"""

import asyncio
import random
import sys
import datetime
import json
from bleak import BleakClient

TARGET_MAC = "${mac}"
TARGET_UUID = "${uuid}"
ITERATIONS = ${iterations}


def generate_boundary():
    """Boundary value fuzzing."""
    values = [
        b"",
        b"\\x00",
        b"\\xff",
        b"\\x00" * 20,
        b"\\xff" * 20,
        b"\\x00" * 255,
        b"\\xff" * 255,
        b"\\x7f",
        b"\\x80",
        b"\\x00\\x00",
        b"\\xff\\xff",
        bytes(range(256)),
    ]
    for v in values:
        yield v


def generate_overflow():
    """Buffer overflow fuzzing with increasing sizes."""
    for i in range(12):
        size = min(2 ** i, 4096)
        yield b"\\x41" * size


def generate_random(count):
    """Random byte fuzzing."""
    for _ in range(count):
        length = random.randint(1, 100)
        yield bytes(random.randint(0, 255) for _ in range(length))


def generate_type_aware(count):
    """Combined strategy: boundary + overflow + random."""
    yield from generate_boundary()
    yield from generate_overflow()
    remaining = max(0, count - 12 - 12)
    yield from generate_random(remaining)


STRATEGIES = {
    "boundary": lambda n: generate_boundary(),
    "overflow": lambda n: generate_overflow(),
    "random": generate_random,
    "type_aware": generate_type_aware,
}


async def main():
    results = {
        "target_mac": TARGET_MAC,
        "target_uuid": TARGET_UUID,
        "start_time": datetime.datetime.utcnow().isoformat() + "Z",
        "iterations_completed": 0,
        "crashes": [],
        "errors": [],
    }

    async with BleakClient(TARGET_MAC) as client:
        print(f"Connected to {TARGET_MAC}", file=sys.stderr)

        for strategy_name in ${JSON.stringify(strategies)}:
            gen = STRATEGIES[strategy_name](ITERATIONS)
            print(f"Running {strategy_name} strategy...", file=sys.stderr)

            for i, fuzz_data in enumerate(gen):
                try:
                    await client.write_gatt_char(TARGET_UUID, fuzz_data, response=True)
                    results["iterations_completed"] += 1
                except Exception as e:
                    err_str = str(e).lower()
                    entry = {
                        "iteration": i,
                        "strategy": strategy_name,
                        "input_hex": fuzz_data.hex(),
                        "error": str(e),
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    }
                    if "disconnect" in err_str or "not connected" in err_str:
                        entry["type"] = "crash"
                        results["crashes"].append(entry)
                        print(f"CRASH at {strategy_name}[{i}]: {e}", file=sys.stderr)
                        break
                    else:
                        entry["type"] = "error"
                        results["errors"].append(entry)

                await asyncio.sleep(0.05)

    results["end_time"] = datetime.datetime.utcnow().isoformat() + "Z"
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
`;
}

export const generateFuzzHarness = {
  name: 'caeruleus.generate_fuzz_harness',
  description:
    'Generate reusable Python fuzzing harness scripts for each writable characteristic from GATT map.',
  parameters: generateFuzzHarnessParams,

  async execute(input: GenerateFuzzHarnessInput): Promise<Record<string, unknown>> {
    const validated = generateFuzzHarnessParams.parse(input);

    const gattRaw = await readFile(validated.gatt_map_path, 'utf-8');
    const gattMap = JSON.parse(gattRaw);

    await mkdir(validated.output_dir, { recursive: true });

    const generated: Array<Record<string, unknown>> = [];
    const mac = gattMap.device_mac || 'XX:XX:XX:XX:XX:XX';

    for (const svc of gattMap.services || []) {
      for (const char of svc.characteristics || []) {
        const props = char.properties || {};
        if (!props.write && !props.write_no_response) continue;

        const safeName = (char.name || char.uuid)
          .replace(/[^a-zA-Z0-9]/g, '_')
          .toLowerCase();
        const filename = `fuzz-${safeName}.py`;
        const filepath = join(validated.output_dir, filename);

        const script = generateHarnessScript(
          mac,
          char.uuid,
          char.name,
          validated.strategies,
          validated.iterations,
        );

        await writeFile(filepath, script, 'utf-8');

        generated.push({
          filename,
          uuid: char.uuid,
          name: char.name,
          service_uuid: svc.uuid,
          properties: {
            write: props.write,
            write_no_response: props.write_no_response,
          },
        });
      }
    }

    const result = {
      harnesses_generated: generated.length,
      output_dir: validated.output_dir,
      strategies: validated.strategies,
      iterations_per_harness: validated.iterations,
      harnesses: generated,
      estimatedTokens: 0,
    };

    result.estimatedTokens = estimateTokens(result);
    return result;
  },
};

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const input = JSON.parse(process.argv[2] ?? '{}');
  generateFuzzHarness
    .execute(input)
    .then((r) => console.log(JSON.stringify(r, null, 2)))
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }, null, 2));
      process.exit(1);
    });
}
