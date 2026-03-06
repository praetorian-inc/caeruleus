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

    _log(f"Connecting to {target}...")

    # On macOS, CoreBluetooth requires the device to be discovered before connecting.
    # Do a quick scan to populate the system cache if needed.
    if IS_MACOS:
        _log(f"Quick scan to discover {target}...")
        device = await BleakScanner.find_device_by_address(target, timeout=5.0)
        if device is None:
            raise ValueError(f"Device {target} not found during pre-connect scan")

    client_kwargs: dict[str, Any] = {"timeout": 15.0}
    if IS_LINUX:
        client_kwargs["adapter"] = _adapter
    _client = BleakClient(target, **client_kwargs)
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

    global _client, _connected_mac, _gatt_cache
    if _client is not None:
        try:
            await _client.disconnect()
        except Exception:
            pass

    # On macOS, CoreBluetooth requires the device to be discovered before connecting.
    if IS_MACOS:
        _log(f"Quick scan to discover {mac}...")
        device = await BleakScanner.find_device_by_address(mac, timeout=5.0)
        if device is None:
            raise ValueError(f"Device {mac} not found during pre-connect scan")

    def _on_disconnect(client):
        _log(f"Disconnected from {mac}")

    client_kwargs: dict[str, Any] = {"timeout": timeout, "disconnected_callback": _on_disconnect}
    if IS_LINUX:
        client_kwargs["adapter"] = _adapter
    _client = BleakClient(mac, **client_kwargs)
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

    await client.start_notify(uuid, _notification_handler)
    _log(f"Subscribed to {uuid}, collecting for {duration}s...")
    await asyncio.sleep(duration)
    await client.stop_notify(uuid)

    notifications = _notification_buffer.pop(uuid, [])
    return {
        "uuid": uuid,
        "duration_seconds": duration,
        "notification_count": len(notifications),
        "notifications": notifications,
    }


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
# Main event loop
# ---------------------------------------------------------------------------

async def main():
    """Read YAML requests from stdin, dispatch to handlers."""
    _platform = "macOS/CoreBluetooth" if IS_MACOS else "Linux/BlueZ" if IS_LINUX else platform.system()
    _log(f"caeruleus-server starting... (platform={_platform}, adapter={_adapter})")
    _send_response({"id": 0, "status": "ok", "result": {"ready": True, "adapter": _adapter}})

    buffer = ""
    loop = asyncio.get_event_loop()

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        try:
            chunk = await reader.read(4096)
            if not chunk:
                break  # EOF

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

                request_id = request.get("id", 0)
                command = request.get("command", "")
                params = request.get("params", {})

                handler = COMMANDS.get(command)
                if handler is None:
                    _send_error(
                        request_id,
                        "UNKNOWN_COMMAND",
                        f"Unknown command: {command}",
                        suggestion=f"Available: {', '.join(sorted(COMMANDS.keys()))}",
                    )
                    continue

                try:
                    result = await handler(params)
                    _send_ok(request_id, result)
                except Exception as e:
                    _log(f"Command {command} error: {e}")
                    _log(traceback.format_exc())

                    code = "UNKNOWN"
                    recoverable = False
                    err_str = str(e).lower()

                    if "not connected" in err_str or "disconnect" in err_str:
                        code = "CONNECTION_LOST"
                        recoverable = True
                    elif "not found" in err_str:
                        code = "DEVICE_NOT_FOUND"
                        recoverable = True
                    elif "permission" in err_str or "not permitted" in err_str:
                        code = "PERMISSION_DENIED"
                    elif "timeout" in err_str:
                        code = "TIMEOUT"
                        recoverable = True
                    elif "pair" in err_str:
                        code = "PAIRING_FAILED"
                    elif "encrypt" in err_str or "auth" in err_str:
                        code = "ENCRYPTION_ERROR"

                    _send_error(request_id, code, str(e), recoverable=recoverable)

                if command == "shutdown":
                    return

        except Exception as e:
            _log(f"Main loop error: {e}")
            _log(traceback.format_exc())
            break

    # Graceful cleanup on exit
    _log("stdin closed, shutting down...")
    if _client is not None:
        try:
            await _client.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGPIPE, lambda *_: sys.exit(0))

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        _log("caeruleus-server shutting down")
