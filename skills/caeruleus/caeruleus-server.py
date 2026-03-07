#!/usr/bin/env python3
"""
caeruleus-server.py — Persistent BLE server for security testing.

Communicates via YAML over stdin/stdout (same protocol as malum/draco).
Maintains active BLE connection state across multiple command invocations.

Environment variables:
  CAERULEUS_ADAPTER  — BlueZ adapter name (default: hci0)
  CAERULEUS_TRANSPORT — usb or network (default: usb)
  CAERULEUS_DEVICE_ID — Specific adapter ID for multi-adapter setups
"""

import asyncio
import datetime
import os
import platform
import signal
import sys
import traceback
from typing import Any, Callable, Optional

import yaml

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

IS_MACOS = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"


def _utcnow_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.datetime.now(datetime.UTC).isoformat() + "Z"

# ---------------------------------------------------------------------------
# Command registry
# ---------------------------------------------------------------------------

COMMANDS: dict[str, Callable] = {}


def register(name: str):
    """Decorator to register a command handler."""
    def decorator(func: Callable) -> Callable:
        COMMANDS[name] = func
        return func
    return decorator


# ---------------------------------------------------------------------------
# Persistent state
# ---------------------------------------------------------------------------

_client: Any = None          # bleak.BleakClient
_connected_mac: Optional[str] = None
_gatt_cache: Optional[dict] = None
_notification_buffer: dict[str, list] = {}  # uuid -> [notifications]
_pairing_state: Optional[str] = None
_adapter: str = os.environ.get("CAERULEUS_ADAPTER", "hci0")

IDLE_TIMEOUT_S = int(os.environ.get("CAERULEUS_IDLE_TIMEOUT", 1800))  # 30 min default


def _is_connected() -> bool:
    return _client is not None and _client.is_connected


async def _ensure_connected(mac: Optional[str] = None) -> Any:
    """Ensure we have an active connection. Reconnect if dropped."""
    global _client, _connected_mac, _gatt_cache

    target = mac or _connected_mac
    if target is None:
        raise ValueError("No target MAC address. Connect first.")

    if _is_connected() and _connected_mac == target:
        return _client

    # Connection dropped or different target — (re)connect
    if _client is not None:
        try:
            await _client.disconnect()
        except Exception:
            pass

    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakDeviceNotFoundError

    _log(f"Connecting to {target}...")

    client_kwargs: dict[str, Any] = {"timeout": 15.0}
    if IS_LINUX:
        client_kwargs["adapter"] = _adapter

    # Try connecting directly first (CoreBluetooth may have device cached).
    # If that fails on macOS with BleakDeviceNotFoundError, do a full scan
    # and pass the BLEDevice object directly — the most reliable macOS pattern.
    _client = BleakClient(target, **client_kwargs)
    try:
        await _client.connect()
    except (BleakDeviceNotFoundError, Exception) as e:
        if not isinstance(e, BleakDeviceNotFoundError) and "not found" not in str(e).lower():
            raise
        _log(f"Device not cached, running discovery scan for {target}...")
        scanner_kwargs: dict[str, Any] = {"timeout": 10.0}
        if IS_LINUX:
            scanner_kwargs["adapter"] = _adapter
        devices = await BleakScanner.discover(**scanner_kwargs)
        device = next((d for d in devices if d.address == target), None)
        if device is None:
            raise ValueError(f"Device {target} not found during discovery scan")
        _client = BleakClient(device, **client_kwargs)
        await _client.connect()

    _connected_mac = target
    _gatt_cache = None  # Invalidate cache on new connection
    _log(f"Connected to {target}")
    return _client


# ---------------------------------------------------------------------------
# YAML IPC protocol
# ---------------------------------------------------------------------------

DELIMITER = "\n---\n"


def _send_response(response: dict) -> None:
    yaml_str = yaml.safe_dump(response, default_flow_style=False, allow_unicode=True)
    sys.stdout.write(yaml_str)
    sys.stdout.write(DELIMITER)
    sys.stdout.flush()


def _send_ok(request_id: int, result: dict) -> None:
    _send_response({"id": request_id, "status": "ok", "result": result})


def _send_error(
    request_id: int,
    code: str,
    message: str,
    recoverable: bool = False,
    suggestion: Optional[str] = None,
) -> None:
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "recoverable": recoverable,
    }
    if suggestion:
        error["suggestion"] = suggestion
    _send_response({"id": request_id, "status": "error", "error": error})


def _log(msg: str) -> None:
    """Log to stderr (visible to TS client as debug info)."""
    print(f"[caeruleus] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Command handlers — Connection lifecycle
# ---------------------------------------------------------------------------

@register("ping")
async def cmd_ping(params: dict) -> dict:
    return {"pong": True, "connected": _is_connected(), "adapter": _adapter}


@register("get_state")
async def cmd_get_state(params: dict) -> dict:
    return {
        "connected": _is_connected(),
        "connected_mac": _connected_mac,
        "adapter": _adapter,
        "gatt_cached": _gatt_cache is not None,
        "notification_subscriptions": list(_notification_buffer.keys()),
        "pairing_state": _pairing_state,
    }


@register("scan")
async def cmd_scan(params: dict) -> dict:
    from bleak import BleakScanner

    duration = params.get("duration", 10)
    active = params.get("active", False)

    _log(f"Scanning for {duration}s (active={active})...")
    devices_found = []
    seen: dict[str, dict] = {}

    def _detection_callback(device, adv_data):
        addr = str(device.address)
        now = asyncio.get_event_loop().time()
        if addr not in seen:
            seen[addr] = {
                "mac_address": addr,
                "mac_type": "public",  # bleak doesn't reliably expose this
                "device_name": adv_data.local_name,
                "rssi_dbm": adv_data.rssi,
                "tx_power_dbm": adv_data.tx_power,
                "connectable": getattr(adv_data, "connectable", None),
                "service_uuids": list(adv_data.service_uuids or []),
                "manufacturer_data": {
                    str(k): v.hex() for k, v in (adv_data.manufacturer_data or {}).items()
                },
                "service_data": {
                    str(k): v.hex() for k, v in (adv_data.service_data or {}).items()
                },
                "flags": [],
                "first_seen": now,
                "last_seen": now,
                "advertisement_count": 1,
            }
        else:
            seen[addr]["last_seen"] = now
            seen[addr]["advertisement_count"] += 1
            seen[addr]["rssi_dbm"] = adv_data.rssi  # Update RSSI

    scanner_kwargs: dict[str, Any] = {"detection_callback": _detection_callback}
    if IS_LINUX:
        scanner_kwargs["adapter"] = _adapter
    scanner = BleakScanner(**scanner_kwargs)
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()

    devices_found = list(seen.values())
    _log(f"Scan complete: {len(devices_found)} devices found")
    return {
        "scan_duration_seconds": duration,
        "adapter": _adapter,
        "device_count": len(devices_found),
        "devices": devices_found,
    }


@register("connect")
async def cmd_connect(params: dict) -> dict:
    mac = params.get("mac_address")
    if not mac:
        raise ValueError("mac_address is required")

    timeout = params.get("timeout", 15)

    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakDeviceNotFoundError

    global _client, _connected_mac, _gatt_cache
    if _client is not None:
        try:
            await _client.disconnect()
        except Exception:
            pass

    def _on_disconnect(client):
        _log(f"Disconnected from {mac}")

    client_kwargs: dict[str, Any] = {"timeout": timeout, "disconnected_callback": _on_disconnect}
    if IS_LINUX:
        client_kwargs["adapter"] = _adapter

    # Try connecting directly first (CoreBluetooth may have device cached).
    # If that fails on macOS with BleakDeviceNotFoundError, do a full scan
    # and pass the BLEDevice object directly — the most reliable macOS pattern.
    _client = BleakClient(mac, **client_kwargs)
    try:
        await _client.connect()
    except (BleakDeviceNotFoundError, Exception) as e:
        if not isinstance(e, BleakDeviceNotFoundError) and "not found" not in str(e).lower():
            raise
        _log(f"Device not cached, running discovery scan for {mac}...")
        scan_kwargs: dict[str, Any] = {"timeout": 10.0}
        if IS_LINUX:
            scan_kwargs["adapter"] = _adapter
        devices = await BleakScanner.discover(**scan_kwargs)
        device = next((d for d in devices if d.address == mac), None)
        if device is None:
            raise ValueError(f"Device {mac} not found during discovery scan")
        _client = BleakClient(device, **client_kwargs)
        await _client.connect()

    _connected_mac = mac
    _gatt_cache = None
    _log(f"Connected to {mac}")

    return {
        "connected": True,
        "mac_address": mac,
        "mtu": _client.mtu_size,
    }


@register("disconnect")
async def cmd_disconnect(params: dict) -> dict:
    global _client, _connected_mac, _gatt_cache, _notification_buffer
    mac = _connected_mac

    if _client is not None:
        try:
            await _client.disconnect()
        except Exception:
            pass
        _client = None

    _connected_mac = None
    _gatt_cache = None
    _notification_buffer.clear()

    return {"disconnected": True, "mac_address": mac}


# ---------------------------------------------------------------------------
# Command handlers — GATT operations
# ---------------------------------------------------------------------------

# Known standard service UUIDs (short form)
STANDARD_SERVICE_UUIDS = {
    "00001800": "Generic Access",
    "00001801": "Generic Attribute",
    "0000180a": "Device Information",
    "0000180f": "Battery Service",
    "00001810": "Blood Pressure",
    "00001816": "Cycling Speed and Cadence",
    "0000181a": "Environmental Sensing",
    "0000181c": "User Data",
    "0000fe59": "Nordic DFU",
}

# Known standard characteristic UUIDs
STANDARD_CHAR_UUIDS = {
    "00002a00": "Device Name",
    "00002a01": "Appearance",
    "00002a04": "Peripheral Preferred Connection Parameters",
    "00002a05": "Service Changed",
    "00002a19": "Battery Level",
    "00002a24": "Model Number String",
    "00002a25": "Serial Number String",
    "00002a26": "Firmware Revision String",
    "00002a27": "Hardware Revision String",
    "00002a28": "Software Revision String",
    "00002a29": "Manufacturer Name String",
}


def _uuid_short(uuid: str) -> Optional[str]:
    """Extract short UUID if it's a standard 128-bit BT SIG UUID."""
    uuid_lower = uuid.lower().replace("-", "")
    if uuid_lower.endswith("00001000800000805f9b34fb"):
        short = uuid_lower[:8]
        return f"0x{short[4:].upper()}"
    return None


def _uuid_name(uuid: str) -> Optional[str]:
    """Look up well-known UUID name."""
    uuid_lower = uuid.lower().replace("-", "")
    prefix = uuid_lower[:8]
    name = STANDARD_SERVICE_UUIDS.get(prefix) or STANDARD_CHAR_UUIDS.get(prefix)
    return name


def _is_standard_service(uuid: str) -> bool:
    uuid_lower = uuid.lower().replace("-", "")
    return uuid_lower[:8] in STANDARD_SERVICE_UUIDS


def _char_properties(char) -> dict:
    """Extract characteristic properties from bleak characteristic."""
    props = char.properties
    return {
        "broadcast": "broadcast" in props,
        "read": "read" in props,
        "write_no_response": "write-without-response" in props,
        "write": "write" in props,
        "notify": "notify" in props,
        "indicate": "indicate" in props,
        "authenticated_signed_writes": "authenticated-signed-writes" in props,
        "extended_properties": "extended-properties" in props,
    }


@register("get_gatt_map")
async def cmd_get_gatt_map(params: dict) -> dict:
    global _gatt_cache
    client = await _ensure_connected(params.get("mac_address"))

    if _gatt_cache is not None and not params.get("force_refresh", False):
        return _gatt_cache

    services_out = []
    total_chars = 0
    readable = writable = notifiable = indicatable = 0
    standard_svcs = custom_svcs = 0

    for service in client.services:
        is_std = _is_standard_service(service.uuid)
        if is_std:
            standard_svcs += 1
        else:
            custom_svcs += 1

        chars_out = []
        for char in service.characteristics:
            total_chars += 1
            props = _char_properties(char)
            if props["read"]:
                readable += 1
            if props["write"] or props["write_no_response"]:
                writable += 1
            if props["notify"]:
                notifiable += 1
            if props["indicate"]:
                indicatable += 1

            # Try to read value
            value_data = None
            if props["read"]:
                try:
                    raw = await client.read_gatt_char(char.uuid)
                    value_data = {
                        "raw_hex": raw.hex(),
                        "decoded": _try_decode(raw),
                        "encoding": "utf-8" if _try_decode(raw) else None,
                    }
                except Exception as e:
                    value_data = {"raw_hex": "", "decoded": None, "encoding": None, "error": str(e)}

            # Descriptors
            descs_out = []
            for desc in char.descriptors:
                desc_val = None
                try:
                    desc_raw = await client.read_gatt_descriptor(desc.handle)
                    desc_val = desc_raw.hex()
                except Exception:
                    pass
                descs_out.append({
                    "uuid": str(desc.uuid),
                    "name": _uuid_name(str(desc.uuid)),
                    "handle": f"0x{desc.handle:04X}",
                    "value_hex": desc_val,
                })

            chars_out.append({
                "uuid": str(char.uuid),
                "uuid_short": _uuid_short(str(char.uuid)),
                "name": _uuid_name(str(char.uuid)),
                "handle": f"0x{char.handle:04X}",
                "value_handle": f"0x{(char.handle + 1):04X}",
                "properties": props,
                "security": {
                    "read_requires": "none",   # Determined by probe_permissions
                    "write_requires": "none",
                },
                "value": value_data,
                "descriptors": descs_out,
            })

        services_out.append({
            "uuid": str(service.uuid),
            "uuid_short": _uuid_short(str(service.uuid)),
            "name": _uuid_name(str(service.uuid)),
            "type": "standard" if is_std else "custom",
            "handle_start": f"0x{service.handle:04X}" if hasattr(service, "handle") else "0x0000",
            "handle_end": "0xFFFF",
            "characteristics": chars_out,
        })

    result = {
        "schema_version": "1.0",
        "device_mac": _connected_mac,
        "connection_timestamp": _utcnow_iso(),
        "mtu": client.mtu_size,
        "services": services_out,
        "summary": {
            "total_services": len(services_out),
            "standard_services": standard_svcs,
            "custom_services": custom_svcs,
            "total_characteristics": total_chars,
            "readable": readable,
            "writable": writable,
            "notifiable": notifiable,
            "indicatable": indicatable,
        },
    }
    _gatt_cache = result
    return result


@register("read_characteristic")
async def cmd_read_characteristic(params: dict) -> dict:
    client = await _ensure_connected(params.get("mac_address"))
    uuid = params.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    # macOS/CoreBluetooth hides GAP service (0x1800) from applications.
    # Fall back to advertisement/peripheral name for Device Name (0x2A00).
    GAP_DEVICE_NAME = "00002a00-0000-1000-8000-00805f9b34fb"
    if uuid.lower().replace("-", "") == GAP_DEVICE_NAME.lower().replace("-", ""):
        char = client.services.get_characteristic(uuid)
        if char is None and IS_MACOS:
            _log("0x2A00 not in service tree (macOS hides GAP). "
                 "Falling back to peripheral name.")
            # On macOS, bleak exposes the name from CoreBluetooth's peripheral
            name = getattr(client, '_device_info', {}).get('name', '')
            if not name:
                # Try the backend peripheral's name directly
                try:
                    name = client._backend._peripheral.name() or ''
                except Exception:
                    name = ''
            if not name:
                name = _connected_mac or 'unknown'
            raw = name.encode('utf-8')
            return {
                "uuid": uuid,
                "raw_hex": raw.hex(),
                "decoded": name,
                "length": len(raw),
                "note": "Read via CoreBluetooth peripheral name (GAP service hidden on macOS)",
            }

    raw = await client.read_gatt_char(uuid)
    return {
        "uuid": uuid,
        "raw_hex": raw.hex(),
        "decoded": _try_decode(raw),
        "length": len(raw),
    }


@register("write_characteristic")
async def cmd_write_characteristic(params: dict) -> dict:
    client = await _ensure_connected(params.get("mac_address"))
    uuid = params.get("uuid")
    value_hex = params.get("value_hex", "")
    response = params.get("response", True)

    if not uuid:
        raise ValueError("uuid is required")

    data = bytes.fromhex(value_hex)
    await client.write_gatt_char(uuid, data, response=response)
    return {
        "uuid": uuid,
        "written_hex": value_hex,
        "length": len(data),
        "with_response": response,
    }


@register("write_no_response")
async def cmd_write_no_response(params: dict) -> dict:
    client = await _ensure_connected(params.get("mac_address"))
    uuid = params.get("uuid")
    value_hex = params.get("value_hex", "")

    if not uuid:
        raise ValueError("uuid is required")

    data = bytes.fromhex(value_hex)
    await client.write_gatt_char(uuid, data, response=False)
    return {"uuid": uuid, "written_hex": value_hex, "length": len(data)}


@register("read_handle")
async def cmd_read_handle(params: dict) -> dict:
    """Read from a raw ATT handle (characteristic value or descriptor)."""
    client = await _ensure_connected(params.get("mac_address"))
    handle = int(params.get("handle", 0))

    if not handle:
        raise ValueError("handle (integer) is required")

    # Try as characteristic (bleak indexes by declaration handle)
    for service in client.services:
        for char in service.characteristics:
            # Value handle is declaration handle + 1
            if char.handle == handle or (char.handle + 1) == handle:
                data = await client.read_gatt_char(char)
                return {
                    "handle": handle,
                    "type": "characteristic",
                    "uuid": str(char.uuid),
                    "raw_hex": data.hex(),
                    "decoded": _try_decode(data),
                    "length": len(data),
                }
            for desc in char.descriptors:
                if desc.handle == handle:
                    data = await client.read_gatt_descriptor(desc)
                    return {
                        "handle": handle,
                        "type": "descriptor",
                        "uuid": str(desc.uuid),
                        "raw_hex": data.hex(),
                        "decoded": _try_decode(data),
                        "length": len(data),
                    }

    raise ValueError(
        f"Handle {handle} (0x{handle:04X}) not found in discovered GATT attributes. "
        f"Only handles present in the service tree can be accessed."
    )


@register("write_handle")
async def cmd_write_handle(params: dict) -> dict:
    """Write to a raw ATT handle (characteristic value or descriptor)."""
    client = await _ensure_connected(params.get("mac_address"))
    handle = int(params.get("handle", 0))
    value_hex = params.get("value_hex", "")

    if not handle:
        raise ValueError("handle (integer) is required")

    data = bytes.fromhex(value_hex)

    # Try as characteristic
    for service in client.services:
        for char in service.characteristics:
            if char.handle == handle or (char.handle + 1) == handle:
                await client.write_gatt_char(char, data, response=True)
                return {
                    "handle": handle,
                    "type": "characteristic",
                    "uuid": str(char.uuid),
                    "written_hex": value_hex,
                    "length": len(data),
                }
            for desc in char.descriptors:
                if desc.handle == handle:
                    await client.write_gatt_descriptor(desc, data)
                    return {
                        "handle": handle,
                        "type": "descriptor",
                        "uuid": str(desc.uuid),
                        "written_hex": value_hex,
                        "length": len(data),
                    }

    raise ValueError(
        f"Handle {handle} (0x{handle:04X}) not found in discovered GATT attributes. "
        f"Only handles present in the service tree can be accessed."
    )


@register("subscribe")
async def cmd_subscribe(params: dict) -> dict:
    client = await _ensure_connected(params.get("mac_address"))
    uuid = params.get("uuid")
    duration = params.get("duration", 30)

    if not uuid:
        raise ValueError("uuid is required")

    _notification_buffer[uuid] = []

    def _notification_handler(sender, data: bytearray):
        _notification_buffer[uuid].append({
            "timestamp": _utcnow_iso(),
            "raw_hex": data.hex(),
            "decoded": _try_decode(data),
            "length": len(data),
        })

    subscribed = False
    subscribe_errors = []

    # Attempt 0: release any stale notify session
    try:
        await client.stop_notify(uuid)
        _log(f"Released stale notify session for {uuid}")
    except Exception:
        pass

    # Attempt 1: standard start_notify
    try:
        await client.start_notify(uuid, _notification_handler)
        subscribed = True
    except Exception as e:
        subscribe_errors.append(f"start_notify: {e}")
        _log(f"start_notify failed for {uuid}: {e}")

    # Attempt 2: reconnect to clear stale notify state, retry
    if not subscribed:
        _log("Reconnecting to clear stale notify state...")
        try:
            global _client, _gatt_cache
            mac = _connected_mac
            await _client.disconnect()
            _client = None
            _gatt_cache = None
            await asyncio.sleep(1)
            client = await _ensure_connected(mac)
            await client.start_notify(uuid, _notification_handler)
            subscribed = True
            _log(f"start_notify succeeded after reconnect for {uuid}")
        except Exception as e:
            _log(f"start_notify still failed after reconnect: {e}")

    # Attempt 3: manual CCCD enable via descriptor write
    if not subscribed:
        subscribed = await _try_manual_cccd_enable(client, uuid, _notification_handler)

    # Attempt 4 (Linux): fall back to raw L2CAP ATT socket
    if not subscribed and IS_LINUX:
        _log(f"Falling back to subscribe_raw (L2CAP ATT) for {uuid}")
        _notification_buffer.pop(uuid, None)
        return await cmd_subscribe_raw({
            "mac_address": _connected_mac,
            "uuid": uuid,
            "duration": duration,
            "write_handle": params.get("write_handle"),
            "write_value_hex": params.get("write_value_hex"),
        })

    if not subscribed:
        _notification_buffer.pop(uuid, None)
        platform_hint = (
            "On macOS/CoreBluetooth, this happens when the remote device lacks "
            "CCCD descriptors (0x2902). CoreBluetooth cannot enable notifications "
            "without a discoverable CCCD. Use Linux/BlueZ for raw ATT handle access."
        )
        raise ValueError(
            f"Cannot subscribe to {uuid}: all notification enable strategies "
            f"failed. {platform_hint} Errors: {'; '.join(subscribe_errors)}"
        )

    _log(f"Subscribed to {uuid}, collecting for {duration}s...")
    await asyncio.sleep(duration)

    try:
        await client.stop_notify(uuid)
    except Exception:
        pass

    notifications = _notification_buffer.pop(uuid, [])
    return {
        "uuid": uuid,
        "duration_seconds": duration,
        "notification_count": len(notifications),
        "notifications": notifications,
    }


async def _try_manual_cccd_enable(client, uuid: str, callback) -> bool:
    """Try to enable notifications by manually writing to the CCCD descriptor."""
    char = client.services.get_characteristic(uuid)
    if not char:
        _log(f"Characteristic {uuid} not found in service tree")
        return False

    props = char.properties
    is_indicate = "indicate" in props
    cccd_value = b'\x02\x00' if is_indicate and "notify" not in props else b'\x01\x00'

    # Strategy A: check for existing CCCD descriptor in bleak's tree
    for desc in char.descriptors:
        if "2902" in str(desc.uuid).lower():
            try:
                await client.write_gatt_descriptor(desc, cccd_value)
                _log(f"Manual CCCD write succeeded via discovered descriptor "
                     f"at handle {desc.handle}")
                return True
            except Exception as e:
                _log(f"CCCD descriptor write failed: {e}")

    # Strategy B: try computed CCCD handle (value_handle + 1 = declaration + 2)
    cccd_handle = char.handle + 2
    _log(f"No CCCD in descriptor list. Trying computed handle "
         f"{cccd_handle} (0x{cccd_handle:04X})...")

    # Check if this handle is already claimed by another attribute
    handle_collision = False
    for service in client.services:
        for c in service.characteristics:
            if c.handle == cccd_handle:
                handle_collision = True
                _log(f"Handle {cccd_handle} is another characteristic declaration — "
                     f"attempting CCCD write anyway (CTF/non-standard device)")

    # Try writing CCCD value to computed handle as descriptor
    try:
        await client.write_gatt_descriptor(cccd_handle, cccd_value)
        _log(f"Manual CCCD write to handle {cccd_handle} succeeded"
             f"{' (despite handle collision)' if handle_collision else ''}")
        return True
    except Exception as e:
        _log(f"Manual CCCD write to handle {cccd_handle} failed: {e}")

    return False


@register("subscribe_raw")
async def cmd_subscribe_raw(params: dict) -> dict:
    """Subscribe to notifications via raw L2CAP ATT socket.

    Bypasses BlueZ D-Bus entirely — opens a direct ATT channel to the
    device, optionally writes a trigger value, and captures ATT Handle
    Value Notification (opcode 0x1B) and Indication (0x1D) PDUs.

    This is the Python equivalent of:
      gatttool -b <mac> -a <handle> --char-write-req -n <value> --listen

    Required on devices that lack CCCD descriptors (common in CTF boards
    and some IoT firmware) where Bleak's start_notify fails.
    """
    import struct
    import socket as sock_mod
    import ctypes
    import ctypes.util
    global _client, _connected_mac, _gatt_cache

    if not IS_LINUX:
        raise ValueError("subscribe_raw requires Linux/BlueZ")

    mac = params.get("mac_address") or _connected_mac
    uuid = params.get("uuid")
    duration = params.get("duration", 30)
    write_value_hex = params.get("write_value_hex")

    if not mac:
        raise ValueError("mac_address is required")

    # Resolve the value handle from UUID via the active Bleak connection
    value_handle = params.get("write_handle")
    if uuid and _client and _client.is_connected:
        char = _client.services.get_characteristic(uuid)
        if char and value_handle is None:
            value_handle = char.handle + 1  # value handle = declaration + 1

    if value_handle is None:
        raise ValueError("Could not resolve value handle — provide write_handle or uuid")
    value_handle = int(value_handle)

    # Disconnect Bleak so we can open a raw ATT socket (one connection at a time)
    if _client and _client.is_connected:
        await _client.disconnect()
    _client = None
    _gatt_cache = None

    _log(f"subscribe_raw: opening L2CAP ATT socket to {mac}, "
         f"value_handle=0x{value_handle:04x}, duration={duration}s")

    # ATT/L2CAP constants
    AF_BLUETOOTH = 31
    ATT_CID = 4
    BDADDR_LE_PUBLIC = 1
    ATT_OP_WRITE_REQ = 0x12
    ATT_OP_WRITE_RESP = 0x13
    ATT_OP_NOTIFICATION = 0x1B
    ATT_OP_INDICATION = 0x1D
    ATT_OP_CONFIRM = 0x1E

    notifications: list[dict] = []
    loop = asyncio.get_event_loop()

    # Open raw L2CAP ATT socket with ctypes for BLE-specific sockaddr_l2
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    raw = sock_mod.socket(sock_mod.AF_BLUETOOTH, sock_mod.SOCK_SEQPACKET,
                          sock_mod.BTPROTO_L2CAP)
    raw.setblocking(False)
    fd = raw.fileno()

    try:
        # Bind with CID=4 (ATT) using packed sockaddr_l2
        local_addr = struct.pack("<HH6sHBx", AF_BLUETOOTH, 0,
                                 b"\x00" * 6, ATT_CID, 0)
        ret = libc.bind(fd, local_addr, len(local_addr))
        if ret != 0:
            raise OSError(ctypes.get_errno(),
                          f"L2CAP bind failed: {os.strerror(ctypes.get_errno())}")

        # Connect with BLE address type
        mac_bytes = bytes(reversed(bytes.fromhex(mac.replace(":", ""))))
        remote_addr = struct.pack("<HH6sHBx", AF_BLUETOOTH, 0,
                                  mac_bytes, ATT_CID, BDADDR_LE_PUBLIC)
        ret = libc.connect(fd, remote_addr, len(remote_addr))
        errno_val = ctypes.get_errno()

        if ret == -1 and errno_val == 115:  # EINPROGRESS
            connect_event = asyncio.Event()
            loop.add_writer(fd, connect_event.set)
            try:
                await asyncio.wait_for(connect_event.wait(), timeout=15.0)
            finally:
                loop.remove_writer(fd)
            err = raw.getsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_ERROR)
            if err:
                raise OSError(err, f"L2CAP connect failed: {os.strerror(err)}")
        elif ret != 0:
            raise OSError(errno_val, f"L2CAP connect failed: {os.strerror(errno_val)}")

        _log("subscribe_raw: ATT socket connected")

        # Write trigger value if provided
        if write_value_hex:
            write_data = bytes.fromhex(write_value_hex)
            att_write = (bytes([ATT_OP_WRITE_REQ])
                         + struct.pack("<H", value_handle)
                         + write_data)
            raw.send(att_write)
            _log(f"subscribe_raw: sent ATT Write Request to 0x{value_handle:04x}")

        # Listen for notifications/indications
        done = asyncio.Event()

        def _on_att_data():
            try:
                data = raw.recv(512)
                if not data:
                    done.set()
                    return
                opcode = data[0]
                if opcode in (ATT_OP_NOTIFICATION, ATT_OP_INDICATION):
                    handle = struct.unpack("<H", data[1:3])[0]
                    payload = data[3:]
                    notifications.append({
                        "timestamp": _utcnow_iso(),
                        "handle": f"0x{handle:04x}",
                        "type": "notification" if opcode == ATT_OP_NOTIFICATION else "indication",
                        "raw_hex": payload.hex(),
                        "decoded": _try_decode(payload),
                        "length": len(payload),
                    })
                    if opcode == ATT_OP_INDICATION:
                        raw.send(bytes([ATT_OP_CONFIRM]))
                elif opcode == ATT_OP_WRITE_RESP:
                    _log("subscribe_raw: received ATT Write Response")
            except (OSError, BlockingIOError):
                pass

        loop.add_reader(fd, _on_att_data)
        try:
            await asyncio.wait_for(done.wait(), timeout=duration)
        except asyncio.TimeoutError:
            pass
        finally:
            loop.remove_reader(fd)

    finally:
        raw.close()

    # Tear down any lingering BlueZ/kernel-level HCI connection left by the
    # raw L2CAP socket before attempting Bleak reconnect.  Without this,
    # single-connection peripherals stay "connected" at the BlueZ level and
    # stop advertising, causing the next Bleak scan to fail with
    # DEVICE_NOT_FOUND.
    _client = None
    _gatt_cache = None
    _connected_mac = mac
    if IS_LINUX and mac:
        try:
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "disconnect", mac,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            _log(f"subscribe_raw: bluetoothctl disconnect {mac} (post-raw cleanup)")
        except Exception as e:
            _log(f"subscribe_raw: bluetoothctl cleanup error (non-fatal): {e}")
        # Short delay to let the device resume advertising
        await asyncio.sleep(1)

    try:
        await _ensure_connected(mac)
        _log("subscribe_raw: reconnected via Bleak")
    except Exception as e:
        _log(f"subscribe_raw: Bleak reconnect failed (non-fatal): {e}")
        # Ensure next command triggers a fresh connection attempt
        _client = None
        _connected_mac = None

    return {
        "uuid": uuid,
        "duration_seconds": duration,
        "notification_count": len(notifications),
        "notifications": notifications,
        "method": "raw_l2cap_att",
    }


@register("raw_att")
async def cmd_raw_att(params: dict) -> dict:
    """Execute raw ATT operations via L2CAP socket.

    Supports a sequence of ATT operations: exchange_mtu, read, write, listen.
    Useful for operations that Bleak doesn't support (MTU negotiation,
    reading handles not in GATT cache, etc.).
    """
    import struct
    import socket as sock_mod
    import ctypes
    import ctypes.util
    global _client, _connected_mac, _gatt_cache

    if not IS_LINUX:
        raise ValueError("raw_att requires Linux/BlueZ")

    mac = params.get("mac_address") or _connected_mac
    if not mac:
        raise ValueError("mac_address is required")

    operations = params.get("operations", [])
    if not operations:
        raise ValueError("operations list is required")

    # Disconnect Bleak so we can open a raw ATT socket
    if _client and _client.is_connected:
        await _client.disconnect()
    _client = None
    _gatt_cache = None

    AF_BLUETOOTH = 31
    ATT_CID = 4
    BDADDR_LE_PUBLIC = 1

    results = []
    loop = asyncio.get_event_loop()
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    raw = sock_mod.socket(sock_mod.AF_BLUETOOTH, sock_mod.SOCK_SEQPACKET,
                          sock_mod.BTPROTO_L2CAP)
    raw.setblocking(False)
    fd = raw.fileno()

    try:
        # Bind
        local_addr = struct.pack("<HH6sHBx", AF_BLUETOOTH, 0,
                                 b"\x00" * 6, ATT_CID, 0)
        ret = libc.bind(fd, local_addr, len(local_addr))
        if ret != 0:
            raise OSError(ctypes.get_errno(),
                          f"L2CAP bind failed: {os.strerror(ctypes.get_errno())}")

        # Connect
        mac_bytes = bytes(reversed(bytes.fromhex(mac.replace(":", ""))))
        remote_addr = struct.pack("<HH6sHBx", AF_BLUETOOTH, 0,
                                  mac_bytes, ATT_CID, BDADDR_LE_PUBLIC)
        ret = libc.connect(fd, remote_addr, len(remote_addr))
        errno_val = ctypes.get_errno()

        if ret == -1 and errno_val == 115:  # EINPROGRESS
            connect_event = asyncio.Event()
            loop.add_writer(fd, connect_event.set)
            try:
                await asyncio.wait_for(connect_event.wait(), timeout=15.0)
            finally:
                loop.remove_writer(fd)
            err = raw.getsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_ERROR)
            if err:
                raise OSError(err, f"L2CAP connect failed: {os.strerror(err)}")
        elif ret != 0:
            raise OSError(errno_val, f"L2CAP connect failed: {os.strerror(errno_val)}")

        _log("raw_att: ATT socket connected")

        async def _recv_att(timeout_s: float = 5.0) -> bytes:
            """Receive one ATT PDU with timeout."""
            data_event = asyncio.Event()
            received = []

            def _on_data():
                try:
                    d = raw.recv(512)
                    received.append(d)
                    data_event.set()
                except (OSError, BlockingIOError):
                    pass

            loop.add_reader(fd, _on_data)
            try:
                await asyncio.wait_for(data_event.wait(), timeout=timeout_s)
                return received[0] if received else b''
            except asyncio.TimeoutError:
                return b''
            finally:
                loop.remove_reader(fd)

        for op in operations:
            op_type = op.get("type")

            if op_type == "exchange_mtu":
                mtu = int(op.get("mtu", 23))
                att_pdu = bytes([0x02]) + struct.pack("<H", mtu)
                raw.send(att_pdu)
                resp = await _recv_att(5.0)
                if resp and resp[0] == 0x03:
                    server_mtu = struct.unpack("<H", resp[1:3])[0]
                    results.append({
                        "type": "exchange_mtu",
                        "requested_mtu": mtu,
                        "server_mtu": server_mtu,
                        "negotiated_mtu": min(mtu, server_mtu),
                    })
                else:
                    results.append({
                        "type": "exchange_mtu",
                        "error": f"Unexpected response: {resp.hex() if resp else 'timeout'}",
                    })

            elif op_type == "read":
                handle = int(op.get("handle", 0))
                att_pdu = bytes([0x0A]) + struct.pack("<H", handle)
                raw.send(att_pdu)
                resp = await _recv_att(5.0)
                if resp and resp[0] == 0x0B:
                    payload = resp[1:]
                    results.append({
                        "type": "read",
                        "handle": f"0x{handle:04x}",
                        "raw_hex": payload.hex(),
                        "decoded": _try_decode(payload),
                        "length": len(payload),
                    })
                elif resp and resp[0] == 0x01:  # Error Response
                    results.append({
                        "type": "read",
                        "handle": f"0x{handle:04x}",
                        "error": f"ATT error 0x{resp[4]:02x}" if len(resp) > 4 else "ATT error",
                    })
                else:
                    results.append({
                        "type": "read",
                        "handle": f"0x{handle:04x}",
                        "error": f"Unexpected: {resp.hex() if resp else 'timeout'}",
                    })

            elif op_type == "write":
                handle = int(op.get("handle", 0))
                value_hex = op.get("value_hex", "")
                data = bytes.fromhex(value_hex)
                att_pdu = bytes([0x12]) + struct.pack("<H", handle) + data
                raw.send(att_pdu)
                resp = await _recv_att(5.0)
                if resp and resp[0] == 0x13:
                    results.append({
                        "type": "write",
                        "handle": f"0x{handle:04x}",
                        "success": True,
                    })
                else:
                    results.append({
                        "type": "write",
                        "handle": f"0x{handle:04x}",
                        "error": f"Unexpected: {resp.hex() if resp else 'timeout'}",
                    })

            elif op_type == "listen":
                duration = float(op.get("duration", 10))
                notifications = []
                done = asyncio.Event()

                def _on_notif():
                    try:
                        d = raw.recv(512)
                        if not d:
                            done.set()
                            return
                        opcode = d[0]
                        if opcode in (0x1B, 0x1D):
                            h = struct.unpack("<H", d[1:3])[0]
                            payload = d[3:]
                            notifications.append({
                                "handle": f"0x{h:04x}",
                                "type": "notification" if opcode == 0x1B else "indication",
                                "raw_hex": payload.hex(),
                                "decoded": _try_decode(payload),
                            })
                            if opcode == 0x1D:
                                raw.send(bytes([0x1E]))
                    except (OSError, BlockingIOError):
                        pass

                loop.add_reader(fd, _on_notif)
                try:
                    await asyncio.wait_for(done.wait(), timeout=duration)
                except asyncio.TimeoutError:
                    pass
                finally:
                    loop.remove_reader(fd)

                results.append({
                    "type": "listen",
                    "duration": duration,
                    "notifications": notifications,
                    "count": len(notifications),
                })

    finally:
        raw.close()

    # Tear down lingering BlueZ connection before Bleak reconnect (same
    # rationale as subscribe_raw — prevents DEVICE_NOT_FOUND on next call).
    _client = None
    _gatt_cache = None
    _connected_mac = mac
    if IS_LINUX and mac:
        try:
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "disconnect", mac,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            _log(f"raw_att: bluetoothctl disconnect {mac} (post-raw cleanup)")
        except Exception as e:
            _log(f"raw_att: bluetoothctl cleanup error (non-fatal): {e}")
        await asyncio.sleep(1)

    try:
        await _ensure_connected(mac)
        _log("raw_att: reconnected via Bleak")
    except Exception as e:
        _log(f"raw_att: Bleak reconnect failed (non-fatal): {e}")
        _client = None
        _connected_mac = None

    return {"operations": results}


@register("unsubscribe")
async def cmd_unsubscribe(params: dict) -> dict:
    client = await _ensure_connected(params.get("mac_address"))
    uuid = params.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    await client.stop_notify(uuid)
    notifications = _notification_buffer.pop(uuid, [])
    return {"uuid": uuid, "stopped": True, "buffered_count": len(notifications)}


@register("get_notification_buffer")
async def cmd_get_notification_buffer(params: dict) -> dict:
    uuid = params.get("uuid")
    if uuid:
        return {
            "uuid": uuid,
            "notifications": _notification_buffer.get(uuid, []),
            "count": len(_notification_buffer.get(uuid, [])),
        }
    return {
        "subscriptions": {k: len(v) for k, v in _notification_buffer.items()},
        "total": sum(len(v) for v in _notification_buffer.values()),
    }


@register("probe_permissions")
async def cmd_probe_permissions(params: dict) -> dict:
    """Test actual read/write permissions for each characteristic."""
    client = await _ensure_connected(params.get("mac_address"))
    timeout_per = params.get("timeout_per_char", 2)

    results = []
    for service in client.services:
        for char in service.characteristics:
            props = _char_properties(char)
            probe = {
                "uuid": str(char.uuid),
                "handle": f"0x{char.handle:04X}",
                "advertised_properties": props,
                "actual_read": None,
                "actual_write": None,
                "read_error": None,
                "write_error": None,
                "permission_mismatch": False,
            }

            # Test read
            if props["read"]:
                try:
                    await asyncio.wait_for(
                        client.read_gatt_char(char.uuid),
                        timeout=timeout_per,
                    )
                    probe["actual_read"] = "success"
                except asyncio.TimeoutError:
                    probe["actual_read"] = "timeout"
                    probe["read_error"] = "Read timed out"
                except Exception as e:
                    err_str = str(e).lower()
                    if "auth" in err_str or "encrypt" in err_str:
                        probe["actual_read"] = "requires_auth"
                    elif "not permitted" in err_str or "permission" in err_str:
                        probe["actual_read"] = "denied"
                    else:
                        probe["actual_read"] = "error"
                    probe["read_error"] = str(e)
            else:
                # Try reading even if not advertised
                try:
                    await asyncio.wait_for(
                        client.read_gatt_char(char.uuid),
                        timeout=timeout_per,
                    )
                    probe["actual_read"] = "success_unadvertised"
                    probe["permission_mismatch"] = True
                except Exception:
                    probe["actual_read"] = "not_readable"

            # Test write (only with safe zero-length or current value)
            if props["write"] or props["write_no_response"]:
                try:
                    # Write current value back (safe probe)
                    if probe["actual_read"] == "success":
                        current = await client.read_gatt_char(char.uuid)
                        await asyncio.wait_for(
                            client.write_gatt_char(char.uuid, current, response=props["write"]),
                            timeout=timeout_per,
                        )
                        probe["actual_write"] = "success"
                    else:
                        probe["actual_write"] = "skipped_no_read"
                except asyncio.TimeoutError:
                    probe["actual_write"] = "timeout"
                    probe["write_error"] = "Write timed out"
                except Exception as e:
                    err_str = str(e).lower()
                    if "auth" in err_str or "encrypt" in err_str:
                        probe["actual_write"] = "requires_auth"
                    elif "not permitted" in err_str or "permission" in err_str:
                        probe["actual_write"] = "denied"
                    else:
                        probe["actual_write"] = "error"
                    probe["write_error"] = str(e)

            results.append(probe)

    mismatches = [r for r in results if r["permission_mismatch"]]
    return {
        "total_characteristics": len(results),
        "permission_mismatches": len(mismatches),
        "results": results,
    }


# ---------------------------------------------------------------------------
# Command handlers — Security testing
# ---------------------------------------------------------------------------

@register("pair")
async def cmd_pair(params: dict) -> dict:
    client = await _ensure_connected(params.get("mac_address"))
    global _pairing_state

    if IS_MACOS:
        _log("Pairing: CoreBluetooth handles pairing implicitly on characteristic access")
        _pairing_state = "implicit_macos"
        return {
            "paired": False,
            "mac_address": _connected_mac,
            "platform_note": "CoreBluetooth does not expose explicit pair/unpair. "
                             "Pairing is triggered implicitly when accessing encrypted characteristics.",
        }

    try:
        await client.pair()
        _pairing_state = "paired"
        return {"paired": True, "mac_address": _connected_mac}
    except Exception as e:
        _pairing_state = "failed"
        raise RuntimeError(f"Pairing failed: {e}")


@register("unpair")
async def cmd_unpair(params: dict) -> dict:
    client = await _ensure_connected(params.get("mac_address"))
    global _pairing_state

    if IS_MACOS:
        _log("Unpair: not available on CoreBluetooth — use Bluetooth System Preferences")
        _pairing_state = "unpaired"
        return {
            "unpaired": False,
            "mac_address": _connected_mac,
            "platform_note": "CoreBluetooth does not support programmatic unpairing. "
                             "Remove the device via System Settings > Bluetooth.",
        }

    try:
        await client.unpair()
        _pairing_state = "unpaired"
        return {"unpaired": True, "mac_address": _connected_mac}
    except Exception as e:
        raise RuntimeError(f"Unpair failed: {e}")


@register("test_encryption")
async def cmd_test_encryption(params: dict) -> dict:
    """Test encryption enforcement by reading characteristics before/after pairing."""
    client = await _ensure_connected(params.get("mac_address"))

    results = {
        "encrypted_characteristics": [],
        "unencrypted_characteristics": [],
        "unknown": [],
    }

    for service in client.services:
        for char in service.characteristics:
            if "read" not in char.properties:
                continue
            try:
                await client.read_gatt_char(char.uuid)
                results["unencrypted_characteristics"].append(str(char.uuid))
            except Exception as e:
                err_str = str(e).lower()
                if "encrypt" in err_str or "auth" in err_str:
                    results["encrypted_characteristics"].append(str(char.uuid))
                else:
                    results["unknown"].append({"uuid": str(char.uuid), "error": str(e)})

    return {
        "link_layer_enforced": len(results["encrypted_characteristics"]) > 0,
        "total_readable": (
            len(results["encrypted_characteristics"])
            + len(results["unencrypted_characteristics"])
            + len(results["unknown"])
        ),
        **results,
    }


@register("get_connection_params")
async def cmd_get_connection_params(params: dict) -> dict:
    """Get current connection parameters (where available via BlueZ)."""
    client = await _ensure_connected(params.get("mac_address"))

    result = {
        "mac_address": _connected_mac,
        "mtu": client.mtu_size,
        "connection_interval": None,
        "slave_latency": None,
        "supervision_timeout": None,
    }

    # Try to read from BlueZ D-Bus (Linux only)
    try:
        import subprocess
        hci_output = subprocess.check_output(
            ["hcitool", "conn"], text=True, timeout=5,
        )
        result["raw_hci_conn"] = hci_output.strip()
    except Exception:
        pass

    return result


@register("fuzz_characteristic")
async def cmd_fuzz_characteristic(params: dict) -> dict:
    """Fuzz a single characteristic with generated inputs."""
    client = await _ensure_connected(params.get("mac_address"))

    uuid = params.get("uuid")
    if not uuid:
        raise ValueError("uuid is required")

    strategy = params.get("strategy", "type_aware")
    iterations = params.get("iterations", 100)
    delay_ms = params.get("delay_ms", 50)

    import random

    results = {
        "uuid": uuid,
        "strategy": strategy,
        "iterations_planned": iterations,
        "iterations_completed": 0,
        "anomalies": [],
        "crashes": [],
        "errors": [],
        "start_time": _utcnow_iso(),
    }

    for i in range(iterations):
        # Generate fuzz input based on strategy
        fuzz_data = _generate_fuzz_input(strategy, i)

        try:
            await client.write_gatt_char(uuid, fuzz_data, response=True)
            results["iterations_completed"] += 1
        except Exception as e:
            err_str = str(e).lower()
            entry = {
                "iteration": i,
                "input_hex": fuzz_data.hex(),
                "error": str(e),
                "timestamp": _utcnow_iso(),
            }

            if "disconnect" in err_str or "not connected" in err_str:
                entry["type"] = "crash"
                results["crashes"].append(entry)
                _log(f"CRASH at iteration {i}: {e}")
                break  # Device disconnected/crashed
            else:
                entry["type"] = "error"
                results["errors"].append(entry)

        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)

    results["end_time"] = _utcnow_iso()
    return results


@register("test_auth_bypass")
async def cmd_test_auth_bypass(params: dict) -> dict:
    """Test authentication bypass by accessing protected characteristics without pairing."""
    client = await _ensure_connected(params.get("mac_address"))

    target_uuids = params.get("target_uuids", [])
    results = []

    for uuid in target_uuids:
        test = {"uuid": uuid, "read_without_auth": None, "write_without_auth": None}

        # Test read without authentication
        try:
            data = await client.read_gatt_char(uuid)
            test["read_without_auth"] = {"success": True, "data_hex": data.hex()}
        except Exception as e:
            test["read_without_auth"] = {"success": False, "error": str(e)}

        # Test write without authentication (write 0x00)
        try:
            await client.write_gatt_char(uuid, bytes([0x00]), response=True)
            test["write_without_auth"] = {"success": True}
        except Exception as e:
            test["write_without_auth"] = {"success": False, "error": str(e)}

        results.append(test)

    bypassed = [r for r in results
                if (r["read_without_auth"] and r["read_without_auth"]["success"])
                or (r["write_without_auth"] and r["write_without_auth"]["success"])]

    return {
        "total_tested": len(results),
        "bypassed_count": len(bypassed),
        "results": results,
    }


@register("replay_writes")
async def cmd_replay_writes(params: dict) -> dict:
    """Replay previously captured write sequences."""
    client = await _ensure_connected(params.get("mac_address"))

    writes = params.get("writes", [])  # [{uuid, value_hex}]
    results = []

    for w in writes:
        uuid = w.get("uuid")
        value_hex = w.get("value_hex", "")
        data = bytes.fromhex(value_hex)

        try:
            await client.write_gatt_char(uuid, data, response=True)
            results.append({"uuid": uuid, "value_hex": value_hex, "accepted": True})
        except Exception as e:
            results.append({"uuid": uuid, "value_hex": value_hex, "accepted": False, "error": str(e)})

    accepted = sum(1 for r in results if r["accepted"])
    return {
        "total_replayed": len(results),
        "accepted": accepted,
        "rejected": len(results) - accepted,
        "replay_protection": accepted == 0,
        "results": results,
    }


@register("shutdown")
async def cmd_shutdown(params: dict) -> dict:
    if _client is not None:
        try:
            await _client.disconnect()
        except Exception:
            pass
    return {"shutdown": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _try_decode(data: bytes) -> Optional[str]:
    """Try to decode bytes as UTF-8 string."""
    try:
        text = data.decode("utf-8")
        if all(c.isprintable() or c in "\t\n\r" for c in text):
            return text
    except (UnicodeDecodeError, ValueError):
        pass
    return None


def _generate_fuzz_input(strategy: str, iteration: int) -> bytes:
    """Generate fuzz input bytes based on strategy."""
    import random

    if strategy == "boundary":
        boundary_values = [
            b"",
            b"\x00",
            b"\xff",
            b"\x00" * 20,
            b"\xff" * 20,
            b"\x00" * 255,
            b"\xff" * 255,
            bytes(range(256)),
            b"\x7f",
            b"\x80",
            b"\x00\x00",
            b"\xff\xff",
            b"\x00" * 512,
        ]
        return boundary_values[iteration % len(boundary_values)]

    elif strategy == "overflow":
        # Increasingly large payloads
        size = min(2 ** (iteration % 12), 4096)
        return b"\x41" * size

    elif strategy == "type_aware":
        # Mix of boundary + random
        if iteration % 3 == 0:
            return _generate_fuzz_input("boundary", iteration // 3)
        elif iteration % 3 == 1:
            return _generate_fuzz_input("overflow", iteration // 3)
        else:
            length = random.randint(1, 50)
            return bytes(random.randint(0, 255) for _ in range(length))

    else:  # random
        length = random.randint(1, 100)
        return bytes(random.randint(0, 255) for _ in range(length))


# ---------------------------------------------------------------------------
# Command dispatch (shared between stdin and socket modes)
# ---------------------------------------------------------------------------

SOCKET_PATH = os.environ.get("CAERULEUS_SOCKET", "/tmp/caeruleus.sock")


def _classify_error(e: Exception) -> tuple[str, bool]:
    """Classify an exception into (error_code, recoverable)."""
    err_str = str(e).lower()
    if "not connected" in err_str or "disconnect" in err_str:
        return "CONNECTION_LOST", True
    if "not found" in err_str:
        return "DEVICE_NOT_FOUND", True
    if "permission" in err_str or "not permitted" in err_str:
        return "PERMISSION_DENIED", False
    if "timeout" in err_str:
        return "TIMEOUT", True
    if "pair" in err_str:
        return "PAIRING_FAILED", False
    if "encrypt" in err_str or "auth" in err_str:
        return "ENCRYPTION_ERROR", False
    return "UNKNOWN", False


async def _dispatch_command(request: dict) -> dict:
    """Dispatch a single command and return the response dict."""
    request_id = request.get("id", 0)
    command = request.get("command", "")
    params = request.get("params", {})

    handler = COMMANDS.get(command)
    if handler is None:
        return {
            "id": request_id,
            "status": "error",
            "error": {
                "code": "UNKNOWN_COMMAND",
                "message": f"Unknown command: {command}",
                "recoverable": False,
                "suggestion": f"Available: {', '.join(sorted(COMMANDS.keys()))}",
            },
        }

    try:
        result = await handler(params)
        return {"id": request_id, "status": "ok", "result": result}
    except Exception as e:
        _log(f"Command {command} error: {e}")
        _log(traceback.format_exc())
        code, recoverable = _classify_error(e)
        # Ensure the error message is never empty — some exceptions (e.g.
        # OSError with errno 0, bare Exception()) produce empty str(e).
        message = str(e) or repr(e) or f"{type(e).__name__} (no message)"
        return {
            "id": request_id,
            "status": "error",
            "error": {"code": code, "message": message, "recoverable": recoverable},
        }


async def _cleanup_ble():
    """Disconnect BLE device if connected. Best-effort.

    Uses Bleak disconnect first, then falls back to bluetoothctl to ensure
    the BlueZ/kernel-level HCI connection is torn down even if Bleak is stuck
    (e.g. mid-start_notify on a CCCD-less characteristic).
    """
    global _client
    mac = _connected_mac
    if _client is not None:
        _log("Disconnecting BLE device...")
        try:
            await asyncio.wait_for(_client.disconnect(), timeout=5)
            _log("BLE disconnected cleanly")
        except asyncio.TimeoutError:
            _log("BLE disconnect timed out (Bleak stuck) — falling through to bluetoothctl")
        except Exception as e:
            _log(f"BLE disconnect error (best-effort): {e}")
        _client = None
    # Fallback: ensure BlueZ kernel-level connection is torn down
    if IS_LINUX and mac:
        try:
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "disconnect", mac,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            _log(f"bluetoothctl disconnect {mac} (fallback cleanup)")
        except Exception as e:
            _log(f"bluetoothctl fallback disconnect error (non-fatal): {e}")


def _write_yaml_response(response: dict) -> str:
    """Serialize a response dict to YAML + delimiter."""
    return yaml.safe_dump(response, default_flow_style=False, allow_unicode=True) + DELIMITER


# ---------------------------------------------------------------------------
# Main event loop — stdin mode (for embedded/pipe use)
# ---------------------------------------------------------------------------

async def main_stdin():
    """Read YAML requests from stdin, dispatch to handlers."""
    _platform = "macOS/CoreBluetooth" if IS_MACOS else "Linux/BlueZ" if IS_LINUX else platform.system()
    _log(f"caeruleus-server starting in stdin mode... (platform={_platform}, adapter={_adapter})")

    sys.stdout.write(_write_yaml_response(
        {"id": 0, "status": "ok", "result": {"ready": True, "adapter": _adapter}}
    ))
    sys.stdout.flush()

    buffer = ""
    loop = asyncio.get_event_loop()

    shutdown_event = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown_event.set)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    try:
        while not shutdown_event.is_set():
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if not chunk:
                break

            buffer += chunk.decode("utf-8", errors="replace")

            while DELIMITER in buffer:
                pos = buffer.index(DELIMITER)
                yaml_text = buffer[:pos]
                buffer = buffer[pos + len(DELIMITER):]
                if not yaml_text.strip():
                    continue

                try:
                    request = yaml.safe_load(yaml_text)
                except yaml.YAMLError as e:
                    _log(f"YAML parse error: {e}")
                    continue

                response = await _dispatch_command(request)
                sys.stdout.write(_write_yaml_response(response))
                sys.stdout.flush()

                if request.get("command") == "shutdown":
                    return

    except Exception as e:
        _log(f"Main loop error: {e}")
        _log(traceback.format_exc())
    finally:
        await _cleanup_ble()


# ---------------------------------------------------------------------------
# Main event loop — Unix socket mode (persistent server)
# ---------------------------------------------------------------------------

async def main_socket():
    """Run persistent server on Unix domain socket.

    Multiple clients can connect sequentially.  The BLE connection and all
    server state persist across client connects/disconnects.
    """
    _platform = "macOS/CoreBluetooth" if IS_MACOS else "Linux/BlueZ" if IS_LINUX else platform.system()
    _log(f"caeruleus-server starting in socket mode... (platform={_platform}, adapter={_adapter})")

    # Clean up stale socket file (check if another server is running first)
    if os.path.exists(SOCKET_PATH):
        try:
            r, w = await asyncio.open_unix_connection(SOCKET_PATH)
            w.close()
            await w.wait_closed()
            _log(f"Another server already running on {SOCKET_PATH}")
            sys.exit(1)
        except (ConnectionRefusedError, FileNotFoundError, OSError):
            os.unlink(SOCKET_PATH)

    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown_event.set)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    import time
    _last_activity = time.monotonic()

    def _touch_activity():
        nonlocal _last_activity
        _last_activity = time.monotonic()

    async def _idle_watchdog():
        """Terminate server after IDLE_TIMEOUT_S seconds of inactivity."""
        while not shutdown_event.is_set():
            await asyncio.sleep(60)  # check every minute
            elapsed = time.monotonic() - _last_activity
            if elapsed >= IDLE_TIMEOUT_S:
                _log(f"Idle timeout ({IDLE_TIMEOUT_S}s) reached — shutting down")
                shutdown_event.set()
                return

    async def handle_client(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ):
        peer = writer.get_extra_info("peername")
        _log(f"Client connected: {peer}")
        _touch_activity()
        buffer = ""
        try:
            while not shutdown_event.is_set():
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                if not chunk:
                    break

                buffer += chunk.decode("utf-8", errors="replace")

                while DELIMITER in buffer:
                    pos = buffer.index(DELIMITER)
                    yaml_text = buffer[:pos]
                    buffer = buffer[pos + len(DELIMITER):]
                    if not yaml_text.strip():
                        continue

                    try:
                        request = yaml.safe_load(yaml_text)
                    except yaml.YAMLError as e:
                        _log(f"YAML parse error: {e}")
                        continue

                    _touch_activity()
                    response = await _dispatch_command(request)
                    writer.write(_write_yaml_response(response).encode())
                    await writer.drain()

                    if request.get("command") == "shutdown":
                        shutdown_event.set()
                        return
        except Exception as e:
            _log(f"Client handler error: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            _log(f"Client disconnected: {peer}")

    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)
    _log(f"Listening on {SOCKET_PATH} (idle timeout={IDLE_TIMEOUT_S}s)")

    # Write PID file so clients can detect a running server
    pid_path = SOCKET_PATH + ".pid"
    with open(pid_path, "w") as f:
        f.write(str(os.getpid()))

    watchdog_task = asyncio.create_task(_idle_watchdog())

    try:
        await shutdown_event.wait()
    finally:
        watchdog_task.cancel()
        server.close()
        await server.wait_closed()
        for path in (SOCKET_PATH, pid_path):
            if os.path.exists(path):
                os.unlink(path)
        await _cleanup_ble()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mode = "socket" if "--socket" in sys.argv else "stdin"
    entry = main_socket if mode == "socket" else main_stdin
    try:
        asyncio.run(entry())
    except KeyboardInterrupt:
        pass
    finally:
        _log("caeruleus-server exited")
