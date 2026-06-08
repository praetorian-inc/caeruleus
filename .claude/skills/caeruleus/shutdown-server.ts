/**
 * shutdown-server.ts — Gracefully stop the caeruleus-server
 *
 * Sends the 'shutdown' command which disconnects BLE before exiting.
 * ALWAYS prefer this over `pkill -f caeruleus-server` — hard-killing
 * the server leaves the BLE connection open at the BlueZ/kernel level,
 * which can block subsequent connections to single-connection devices.
 */

import { fileURLToPath } from 'node:url';
import { callBle } from './lib/client.js';

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  callBle('shutdown')
    .then(() => {
      console.log(JSON.stringify({ shutdown: true }));
    })
    .catch((e: unknown) => {
      console.error(JSON.stringify({ error: (e as Error).message }));
      process.exit(1);
    });
}
