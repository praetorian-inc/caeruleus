#!/usr/bin/env python3
"""
caeruleus-sniffer.py — Persistent RF sniffer server for BLE passive capture.

Separate from caeruleus-server.py because RF sniffing uses different hardware
(Ubertooth/nRF52/Sniffle) than GATT interaction (BlueZ adapter).

Communicates via YAML over stdin/stdout (same protocol as caeruleus-server.py).

Environment variables:
  CAERULEUS_SNIFFER_HARDWARE — ubertooth|nrf52|sniffle (default: ubertooth)
"""

import asyncio
import os
import signal
import subprocess
import sys
import traceback
from typing import Any, Callable, Optional

import yaml

# ---------------------------------------------------------------------------
# Command registry
# ---------------------------------------------------------------------------

COMMANDS: dict[str, Callable] = {}


def register(name: str):
    def decorator(func: Callable) -> Callable:
        COMMANDS[name] = func
        return func
    return decorator


# ---------------------------------------------------------------------------
# Persistent state
# ---------------------------------------------------------------------------

_hardware: str = os.environ.get("CAERULEUS_SNIFFER_HARDWARE", "ubertooth")
_capture_process: Optional[subprocess.Popen] = None
_capture_file: Optional[str] = None
_is_capturing: bool = False


# ---------------------------------------------------------------------------
# YAML IPC protocol (identical to caeruleus-server.py)
# ---------------------------------------------------------------------------

DELIMITER = "\n---\n"


def _send_response(response: dict) -> None:
    yaml_str = yaml.dump(response, default_flow_style=False, allow_unicode=True)
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
    error: dict[str, Any] = {"code": code, "message": message, "recoverable": recoverable}
    if suggestion:
        error["suggestion"] = suggestion
    _send_response({"id": request_id, "status": "error", "error": error})


def _log(msg: str) -> None:
    print(f"[caeruleus-sniffer] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

@register("ping")
async def cmd_ping(params: dict) -> dict:
    return {
        "pong": True,
        "hardware": _hardware,
        "capturing": _is_capturing,
        "capture_file": _capture_file,
    }


@register("get_state")
async def cmd_get_state(params: dict) -> dict:
    return {
        "hardware": _hardware,
        "capturing": _is_capturing,
        "capture_file": _capture_file,
        "hardware_available": _detect_hardware(),
    }


@register("start_capture")
async def cmd_start_capture(params: dict) -> dict:
    global _capture_process, _capture_file, _is_capturing

    if _is_capturing:
        raise RuntimeError("Capture already in progress. Stop it first.")

    output_file = params.get("output_file", "/tmp/caeruleus-capture.pcap")
    target_mac = params.get("target_mac")
    channel = params.get("channel")
    mode = params.get("mode", "follow")  # follow|advertisements_only
    duration = params.get("duration")

    cmd: list[str] = []

    if _hardware == "ubertooth":
        cmd = ["ubertooth-btle", "-f", "-c", output_file]
        if target_mac:
            cmd.extend(["-t", target_mac])
        if mode == "advertisements_only":
            cmd = ["ubertooth-btle", "-p", "-c", output_file]
    elif _hardware == "nrf52":
        cmd = ["nrf_sniffer_ble", "--capture", output_file]
        if target_mac:
            cmd.extend(["--target", target_mac])
        if channel:
            cmd.extend(["--channel", str(channel)])
    elif _hardware == "sniffle":
        cmd = ["python3", "-m", "sniffle", "-o", output_file]
        if target_mac:
            cmd.extend(["-t", target_mac])
        if mode == "advertisements_only":
            cmd.append("-a")
    else:
        raise ValueError(f"Unsupported hardware: {_hardware}")

    _log(f"Starting capture: {' '.join(cmd)}")
    _capture_process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _capture_file = output_file
    _is_capturing = True

    # If duration specified, schedule stop
    if duration:
        asyncio.get_event_loop().call_later(
            duration,
            lambda: asyncio.ensure_future(_stop_capture_internal()),
        )

    return {
        "capturing": True,
        "hardware": _hardware,
        "output_file": output_file,
        "target_mac": target_mac,
        "mode": mode,
        "duration": duration,
        "pid": _capture_process.pid,
    }


@register("stop_capture")
async def cmd_stop_capture(params: dict) -> dict:
    return await _stop_capture_internal()


async def _stop_capture_internal() -> dict:
    global _capture_process, _is_capturing

    if not _is_capturing or _capture_process is None:
        return {"stopped": False, "reason": "No capture in progress"}

    _capture_process.terminate()
    try:
        _capture_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _capture_process.kill()
        _capture_process.wait()

    stderr_output = ""
    if _capture_process.stderr:
        stderr_output = _capture_process.stderr.read().decode("utf-8", errors="replace")

    result = {
        "stopped": True,
        "capture_file": _capture_file,
        "hardware": _hardware,
        "exit_code": _capture_process.returncode,
        "stderr": stderr_output[:500],
    }

    # Get file size
    if _capture_file:
        try:
            import os as _os
            stat = _os.stat(_capture_file)
            result["file_size_bytes"] = stat.st_size
        except OSError:
            result["file_size_bytes"] = 0

    _capture_process = None
    _is_capturing = False

    return result


@register("decode_packets")
async def cmd_decode_packets(params: dict) -> dict:
    """Decode captured packets from pcap file."""
    pcap_file = params.get("pcap_file") or _capture_file
    if not pcap_file:
        raise ValueError("No pcap file specified and no active capture")

    max_packets = params.get("max_packets", 100)
    filter_type = params.get("filter", "all")  # all|att|ll|adv

    # Use tshark for decoding
    tshark_cmd = ["tshark", "-r", pcap_file, "-T", "json", "-c", str(max_packets)]

    if filter_type == "att":
        tshark_cmd.extend(["-Y", "btatt"])
    elif filter_type == "ll":
        tshark_cmd.extend(["-Y", "btle"])
    elif filter_type == "adv":
        tshark_cmd.extend(["-Y", "btle.advertising_header"])

    try:
        result = subprocess.run(
            tshark_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        import json
        packets = json.loads(result.stdout) if result.stdout.strip() else []

        return {
            "pcap_file": pcap_file,
            "filter": filter_type,
            "packet_count": len(packets),
            "max_packets": max_packets,
            "packets": packets[:max_packets],
            "tshark_stderr": result.stderr[:200] if result.stderr else None,
        }
    except FileNotFoundError:
        raise RuntimeError("tshark not found. Install Wireshark/tshark for packet decoding.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("tshark decoding timed out")


@register("shutdown")
async def cmd_shutdown(params: dict) -> dict:
    if _is_capturing and _capture_process:
        await _stop_capture_internal()
    return {"shutdown": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_hardware() -> list[str]:
    """Detect available sniffer hardware."""
    available = []

    for tool, hw in [
        ("ubertooth-btle", "ubertooth"),
        ("nrf_sniffer_ble", "nrf52"),
    ]:
        try:
            subprocess.run(
                ["which", tool],
                capture_output=True,
                timeout=5,
            )
            available.append(hw)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Check for Sniffle Python module
    try:
        subprocess.run(
            ["python3", "-c", "import sniffle"],
            capture_output=True,
            timeout=5,
        )
        available.append("sniffle")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return available


# ---------------------------------------------------------------------------
# Main event loop (identical pattern to caeruleus-server.py)
# ---------------------------------------------------------------------------

async def main():
    _log(f"caeruleus-sniffer starting (hardware={_hardware})...")
    _send_response({
        "id": 0,
        "status": "ok",
        "result": {"ready": True, "hardware": _hardware},
    })

    buffer = ""
    loop = asyncio.get_event_loop()

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        try:
            chunk = await reader.read(4096)
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
                    _send_error(
                        request_id,
                        "SNIFFER_ERROR",
                        str(e),
                        recoverable=True,
                    )

                if command == "shutdown":
                    return

        except Exception as e:
            _log(f"Main loop error: {e}")
            break


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        _log("caeruleus-sniffer shutting down")
