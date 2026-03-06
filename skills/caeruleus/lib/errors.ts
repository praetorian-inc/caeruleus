export type BleErrorCode =
  | 'ADAPTER_NOT_FOUND'
  | 'DEVICE_NOT_FOUND'
  | 'CONNECTION_FAILED'
  | 'CONNECTION_LOST'
  | 'GATT_NOT_ACCESSIBLE'
  | 'CHARACTERISTIC_NOT_FOUND'
  | 'WRITE_FAILED'
  | 'READ_FAILED'
  | 'PAIRING_FAILED'
  | 'ENCRYPTION_ERROR'
  | 'PERMISSION_DENIED'
  | 'TIMEOUT'
  | 'INVALID_PARAMS'
  | 'SERVER_NOT_RUNNING'
  | 'SCAN_FAILED'
  | 'SUBSCRIBE_FAILED'
  | 'FUZZ_ABORTED'
  | 'DEVICE_CRASHED'
  | 'SNIFFER_NOT_AVAILABLE'
  | 'UNKNOWN';

export class BleError extends Error {
  constructor(
    public code: BleErrorCode | string,
    message: string,
    public recoverable: boolean = false,
    public suggestion?: string,
  ) {
    super(message);
    this.name = 'BleError';
  }
}

export class BleAdapterNotFoundError extends BleError {
  constructor(adapter: string = 'hci0') {
    super(
      'ADAPTER_NOT_FOUND',
      `BLE adapter ${adapter} not found`,
      false,
      'Check that BlueZ is installed and the adapter is connected: hciconfig -a',
    );
  }
}

export class BleDeviceNotFoundError extends BleError {
  constructor(mac: string) {
    super(
      'DEVICE_NOT_FOUND',
      `BLE device ${mac} not found during scan`,
      true,
      'Ensure device is powered on and within range. Try increasing scan duration.',
    );
  }
}

export class BleConnectionLostError extends BleError {
  constructor(mac: string, reason?: string) {
    super(
      'CONNECTION_LOST',
      `Connection to ${mac} lost${reason ? `: ${reason}` : ''}`,
      true,
      'Will auto-reconnect on next command. If device crashed, power-cycle it.',
    );
  }
}

export class BleDeviceCrashedError extends BleError {
  constructor(mac: string, lastInput?: string) {
    super(
      'DEVICE_CRASHED',
      `Device ${mac} appears to have crashed${lastInput ? ` after input: ${lastInput}` : ''}`,
      true,
      'Power-cycle the device and confirm it is advertising again.',
    );
  }
}

export class BleTimeoutError extends BleError {
  constructor(operation: string, timeoutMs: number) {
    super(
      'TIMEOUT',
      `${operation} timed out after ${timeoutMs}ms`,
      true,
      'The device may be busy or out of range. Try again.',
    );
  }
}

export class BleServerNotRunningError extends BleError {
  constructor() {
    super(
      'SERVER_NOT_RUNNING',
      'caeruleus-server.py is not running',
      true,
      'Server will auto-start on next call.',
    );
  }
}
