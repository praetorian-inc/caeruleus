/**
 * BleClient — Manages persistent caeruleus-server.py process for BLE operations.
 *
 * Communicates via YAML over stdin/stdout following the malum/draco IPC pattern.
 * Auto-starts server on first call, auto-restarts on crash.
 */

import { spawn, type ChildProcess } from 'node:child_process';
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

const DEFAULT_TIMEOUT_MS = 60_000;
const READY_TIMEOUT_MS = 15_000;
const DELIMITER = '\n---\n';

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
}

let _instance: BleClient | null = null;

export class BleClient extends EventEmitter implements IBleClient {
  private process: ChildProcess | null = null;
  private ready = false;
  private buffer = '';
  private pendingResponses: Map<number, PendingRequest> = new Map();
  private requestId = 0;
  private connectedMac: string | null = null;
  private startingPromise: Promise<void> | null = null;

  private readonly python: string;
  private readonly adapter: string;
  private readonly transport: string;
  private readonly deviceId: string;

  constructor() {
    super();
    this.python = process.env.CAERULEUS_PYTHON || 'python3';
    this.adapter = process.env.CAERULEUS_ADAPTER || 'hci0';
    this.transport = process.env.CAERULEUS_TRANSPORT || 'usb';
    this.deviceId = process.env.CAERULEUS_DEVICE_ID || '';
  }

  /** Singleton access */
  static getInstance(): BleClient {
    if (!_instance) {
      _instance = new BleClient();
    }
    return _instance;
  }

  /** Spawn caeruleus-server.py and wait for ready signal */
  private async startServer(): Promise<void> {
    if (this.startingPromise) return this.startingPromise;

    this.startingPromise = (async () => {
      const serverPath = join(__dirname, '..', 'caeruleus-server.py');

      this.process = spawn(this.python, [serverPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          CAERULEUS_ADAPTER: this.adapter,
          CAERULEUS_TRANSPORT: this.transport,
          CAERULEUS_DEVICE_ID: this.deviceId,
        },
      });

      this.process.stderr?.on('data', (data: Buffer) => {
        const msg = data.toString().trim();
        if (msg) {
          console.error(`[caeruleus-server] ${msg}`);
        }
      });

      this.process.stdout?.on('data', (data: Buffer) => {
        this.buffer += data.toString();
        this.processBuffer();
      });

      this.process.on('exit', (code, signal) => {
        console.error(
          `[caeruleus-server] exited (code=${code}, signal=${signal})`,
        );
        this.resetState();
      });

      this.process.on('error', (err) => {
        console.error(`[caeruleus-server] spawn error: ${err.message}`);
        this.resetState();
      });

      // Kill child process when parent exits to prevent orphaned servers
      const cleanup = () => {
        if (this.process && !this.process.killed) {
          this.process.kill();
        }
      };
      process.once('exit', cleanup);
      process.once('SIGTERM', cleanup);
      process.once('SIGINT', cleanup);

      await this.waitForReady();
    })();

    try {
      await this.startingPromise;
    } finally {
      this.startingPromise = null;
    }
  }

  /** Wait for server to send ready signal */
  private waitForReady(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (this.ready) {
        resolve();
        return;
      }

      const timer = setTimeout(() => {
        reject(new BleTimeoutError('Server startup', READY_TIMEOUT_MS));
      }, READY_TIMEOUT_MS);

      this.once('ready', () => {
        clearTimeout(timer);
        resolve();
      });

      this.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
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

  /** Route response to pending promise or handle ready signal */
  private handleResponse(response: CaeruleusResponse): void {
    // Ready signal from server
    if (
      response.status === 'ok' &&
      (response as CaeruleusResponse & { result?: { ready?: boolean } }).result
        ?.ready
    ) {
      this.ready = true;
      this.emit('ready');
      return;
    }

    const id = response.id;
    if (id === undefined || !this.pendingResponses.has(id)) {
      console.error(`[ble-client] Unmatched response id=${id}`);
      return;
    }

    const pending = this.pendingResponses.get(id)!;
    this.pendingResponses.delete(id);
    clearTimeout(pending.timer);

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

  /** Reset state after server exit */
  private resetState(): void {
    this.ready = false;
    this.process = null;
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
    if (!this.process || !this.ready) {
      await this.startServer();
    }

    const id = this.requestId++;
    const request: CaeruleusRequest = {
      id,
      command: params.command,
      params: params.params ?? {},
    };

    const yamlText = YAML.stringify(request);
    this.process!.stdin!.write(yamlText + DELIMITER);

    const timeoutMs =
      (params.params?.timeout_ms as number) || DEFAULT_TIMEOUT_MS;

    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pendingResponses.has(id)) {
          this.pendingResponses.delete(id);
          reject(new BleTimeoutError(params.command, timeoutMs));
        }
      }, timeoutMs);

      this.pendingResponses.set(id, { resolve, reject, timer });
    });
  }

  /** Health check */
  async ping(): Promise<{ pong: boolean; connected: boolean }> {
    return (await this.call({ command: 'ping' })) as {
      pong: boolean;
      connected: boolean;
    };
  }

  /** Graceful shutdown */
  async shutdown(): Promise<void> {
    if (this.process) {
      try {
        await this.call({ command: 'shutdown' });
      } catch {
        // Best-effort
      }
      this.process.kill();
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

/** Convenience function — call BLE server command via singleton client */
export async function callBle(
  command: string,
  params: Record<string, unknown> = {},
): Promise<unknown> {
  const client = BleClient.getInstance();
  return client.call({ command, params });
}
