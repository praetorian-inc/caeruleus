/**
 * BleClient — Connects to persistent caeruleus-server.py via Unix domain socket.
 *
 * The server runs as a detached background process, persisting BLE connections
 * across multiple skill invocations. Auto-starts if not running.
 */

import { spawn, execFile } from 'node:child_process';
import { connect as netConnect, type Socket } from 'node:net';
import { existsSync } from 'node:fs';
import { EventEmitter } from 'node:events';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as YAML from 'yaml';
import type {
  CaeruleusRequest,
  CaeruleusResponse,
  CaeruleusCallParams,
  IBleClient,
} from './types.js';
import { BleError, BleServerNotRunningError, BleTimeoutError } from './errors.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SOCKET_PATH = process.env.CAERULEUS_SOCKET || '/tmp/caeruleus.sock';
const DEFAULT_TIMEOUT_MS = 60_000;
const SERVER_STARTUP_TIMEOUT_MS = 15_000;
const DELIMITER = '\n---\n';

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
}

let _instance: BleClient | null = null;

export class BleClient extends EventEmitter implements IBleClient {
  private socket: Socket | null = null;
  private buffer = '';
  private pendingResponses: Map<number, PendingRequest> = new Map();
  private requestId = 0;
  private connectedMac: string | null = null;
  private connectingPromise: Promise<void> | null = null;

  private readonly python: string;

  constructor() {
    super();
    this.python = process.env.CAERULEUS_PYTHON || 'python3';
  }

  /** Singleton access */
  static getInstance(): BleClient {
    if (!_instance) {
      _instance = new BleClient();
    }
    return _instance;
  }

  /** Ensure connected to server socket, starting server if needed */
  private async ensureSocket(): Promise<void> {
    if (this.socket && !this.socket.destroyed) return;
    if (this.connectingPromise) return this.connectingPromise;

    this.connectingPromise = (async () => {
      // Try connecting to existing server
      try {
        await this.connectToSocket();
        return;
      } catch {
        // No server running, start one
      }

      this.spawnServer();

      // Wait for socket to become available
      const deadline = Date.now() + SERVER_STARTUP_TIMEOUT_MS;
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 300));
        try {
          await this.connectToSocket();
          return;
        } catch {
          // Not ready yet
        }
      }
      throw new BleServerNotRunningError();
    })();

    try {
      await this.connectingPromise;
    } finally {
      this.connectingPromise = null;
    }
  }

  /** Connect to the server's Unix domain socket */
  private connectToSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!existsSync(SOCKET_PATH)) {
        reject(new Error('Socket file does not exist'));
        return;
      }

      const socket = netConnect(SOCKET_PATH);
      const timeout = setTimeout(() => {
        socket.destroy();
        reject(new Error('Socket connection timeout'));
      }, 5000);

      socket.on('connect', () => {
        clearTimeout(timeout);
        this.socket = socket;
        this.buffer = '';

        // Allow Node.js to exit when no requests are pending.
        // The server runs as a detached process and persists independently.
        // We ref/unref dynamically based on pending request count.
        socket.unref();

        socket.on('data', (data: Buffer) => {
          this.buffer += data.toString();
          this.processBuffer();
        });

        socket.on('close', () => {
          this.resetState();
        });

        socket.on('error', (err) => {
          console.error(`[ble-client] socket error: ${err.message}`);
        });

        resolve();
      });

      socket.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
  }

  /** Spawn caeruleus-server.py as a detached background process */
  private spawnServer(): void {
    const serverPath = join(__dirname, '..', 'caeruleus-server.py');
    const child = spawn(this.python, [serverPath, '--socket'], {
      detached: true,
      stdio: 'ignore',
      env: {
        ...process.env,
        CAERULEUS_SOCKET: SOCKET_PATH,
      },
    });
    child.unref();
    console.error(`[ble-client] Started server (pid=${child.pid})`);
  }

  /** Parse YAML documents delimited by \n---\n */
  private processBuffer(): void {
    let pos: number;
    while ((pos = this.buffer.indexOf(DELIMITER)) !== -1) {
      const yamlText = this.buffer.substring(0, pos);
      this.buffer = this.buffer.substring(pos + DELIMITER.length);

      if (!yamlText.trim()) continue;

      try {
        const response = YAML.parse(yamlText) as CaeruleusResponse;
        this.handleResponse(response);
      } catch (err) {
        console.error(
          '[ble-client] YAML parse error:',
          err,
          'raw:',
          yamlText.substring(0, 200),
        );
      }
    }
  }

  /** Route response to pending promise */
  private handleResponse(response: CaeruleusResponse): void {
    const id = response.id;
    if (id === undefined || !this.pendingResponses.has(id)) {
      console.error(`[ble-client] Unmatched response id=${id}`);
      return;
    }

    const pending = this.pendingResponses.get(id)!;
    this.pendingResponses.delete(id);
    clearTimeout(pending.timer);
    this.updateSocketRef();

    if (response.status === 'error' && 'error' in response) {
      const err = response.error;
      pending.reject(
        new BleError(err.code, err.message, err.recoverable, err.suggestion),
      );
    } else if (response.status === 'ok' && 'result' in response) {
      pending.resolve(response.result);
    } else {
      pending.reject(
        new BleError(
          'UNKNOWN',
          `Unexpected response: ${JSON.stringify(response)}`,
        ),
      );
    }
  }

  /** Ref the socket while requests are pending so Node.js doesn't exit early */
  private updateSocketRef(): void {
    if (!this.socket || this.socket.destroyed) return;
    if (this.pendingResponses.size > 0) {
      this.socket.ref();
    } else {
      this.socket.unref();
    }
  }

  /** Reset state after socket close */
  private resetState(): void {
    this.socket = null;
    this.connectedMac = null;
    this.buffer = '';

    for (const [, pending] of this.pendingResponses) {
      clearTimeout(pending.timer);
      pending.reject(new BleServerNotRunningError());
    }
    this.pendingResponses.clear();
  }

  /** Send YAML request to server */
  async call(params: CaeruleusCallParams): Promise<unknown> {
    await this.ensureSocket();

    const id = this.requestId++;
    const request: CaeruleusRequest = {
      id,
      command: params.command,
      params: params.params ?? {},
    };

    const yamlText = YAML.stringify(request);
    this.socket!.write(yamlText + DELIMITER);

    const timeoutMs =
      (params.params?.timeout_ms as number) || DEFAULT_TIMEOUT_MS;

    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pendingResponses.has(id)) {
          this.pendingResponses.delete(id);
          this.updateSocketRef();
          reject(new BleTimeoutError(params.command, timeoutMs));
        }
      }, timeoutMs);

      this.pendingResponses.set(id, { resolve, reject, timer });
      this.updateSocketRef();
    });
  }

  /** Health check */
  async ping(): Promise<{ pong: boolean; connected: boolean }> {
    return (await this.call({ command: 'ping' })) as {
      pong: boolean;
      connected: boolean;
    };
  }

  /** Graceful shutdown — stops the background server process */
  async shutdown(): Promise<void> {
    if (this.socket && !this.socket.destroyed) {
      try {
        await this.call({ command: 'shutdown' });
      } catch {
        // Best-effort
      }
      this.socket.destroy();
      this.resetState();
    }
    _instance = null;
  }

  /** Track connected device MAC for reconnection */
  setConnectedMac(mac: string | null): void {
    this.connectedMac = mac;
  }

  getConnectedMac(): string | null {
    return this.connectedMac;
  }
}

/**
 * Attempt to clear an orphaned BlueZ/kernel-level HCI connection via
 * bluetoothctl.  This is a best-effort recovery — if it fails, we
 * surface the original error.
 */
async function bluetoothctlDisconnect(mac: string): Promise<boolean> {
  if (process.platform !== 'linux') return false;
  return new Promise((resolve) => {
    execFile('bluetoothctl', ['disconnect', mac], { timeout: 5000 }, (err) => {
      resolve(!err);
    });
  });
}

/** Convenience function — call BLE server command via singleton client.
 *
 *  Includes auto-retry logic: if a `connect` command fails with
 *  DEVICE_NOT_FOUND, we attempt a `bluetoothctl disconnect` to clear any
 *  orphaned BlueZ connection (left by a raw L2CAP socket or killed process),
 *  wait briefly for the device to resume advertising, then retry once.
 */
export async function callBle(
  command: string,
  params: Record<string, unknown> = {},
): Promise<unknown> {
  const client = BleClient.getInstance();
  try {
    return await client.call({ command, params });
  } catch (err) {
    const bleErr = err as BleError;
    if (bleErr.code === 'DEVICE_NOT_FOUND' && command === 'connect' && params.mac_address) {
      const mac = params.mac_address as string;
      const cleaned = await bluetoothctlDisconnect(mac);
      if (cleaned) {
        // Wait for device to resume advertising after forced disconnect
        await new Promise((r) => setTimeout(r, 2000));
        return client.call({ command, params });
      }
    }
    throw err;
  }
}
