# Caeruleus quick reference

A single Go binary for BLE work on Linux/BlueZ: scan, browse/read/write GATT,
notifications, security assessment, and fuzzing. One target flag everywhere
(`-b <BDADDR>`) and `-o json` on any command for scripting.

If you already use another BLE tool, jump to the row that matches your habit.

## Coming from another tool?

| If you reach for... | for... | Try in caeruleus |
|---|---|---|
| `bettercap` `ble.recon` | finding devices | `caeruleus scan` |
| `hcitool lescan` | LE device discovery | `caeruleus scan` (add `-t <secs>` for the window) |
| `bettercap` `ble.enum <mac>` | listing services/chars | `caeruleus enumerate -b <mac> --values` |
| `gatttool -I` / `-b <mac> -I` | an interactive session | `caeruleus shell -b <mac>` |
| `gatttool --char-read-hnd 0x0013` | reading a handle | `caeruleus read -b <mac> -a 0x0013` |
| `gatttool --char-write-req 0x15 -n 41` | writing a handle | `caeruleus write -b <mac> -a 0x0015 -n 41 --req` |
| `bluetoothctl` scan/info | discovery + a quick profile | `caeruleus scan` / `caeruleus recon -b <mac>` |
| nRF Connect (GUI) GATT browser | seeing the whole tree + values | `caeruleus enumerate -b <mac> --values` |
| custom Bleak/pygatt script: "what can I read unpaired? any hidden readable chars?" | unauth exposure + audit | `caeruleus recon -b <mac>` and `caeruleus assess check-auth -b <mac>` |
| custom script: "does it enforce pairing/encryption?" | encryption enforcement | `caeruleus assess encryption -b <mac>` |
| `bluetoothctl pair` / `remove` | pairing / bonding tests | `caeruleus pair -b <mac>` / `caeruleus unpair -b <mac>` |
| custom Bleak notification logger | capturing notifications | `caeruleus listen -b <mac> -a 0xHND --duration 10s` |
| `btmon` grep for notifications | catching notifications BlueZ hides | `sudo caeruleus monitor -b <mac>` |
| `nrfutil` / DFU poking | spotting an exposed DFU entry | `caeruleus assess dfu -b <mac>` |
| custom write fuzzers / boofuzz harness | fuzzing a writable characteristic | `caeruleus fuzz write -b <mac> -a 0xHND` |
| `hcitool con` / nRF Connect conn-params | interval / latency / timeout / MTU | `sudo caeruleus conn-params -b <mac>` ; `caeruleus mtu -b <mac> --show` |
| `hciconfig reset` / `rfkill` / power-cycling the dongle | unwedging a stuck adapter | `caeruleus doctor` ; `caeruleus adapter power cycle` ; `caeruleus forget -b <mac>` |
| `bdaddr` (BlueZ tool) | reading / spoofing the adapter MAC | `sudo caeruleus bdaddr --show` / `--set <mac>` |

## A few worked examples

**Recon and read, like `ble.enum` then `gatttool`:**
```bash
caeruleus scan -t 8
caeruleus enumerate -b AA:BB:CC:DD:EE:FF --values   # full GATT + values
caeruleus read  -b AA:BB:CC:DD:EE:FF -a 0x0013      # or  -u 2a00
```

**Interactive, like `gatttool -I` (gatttool-style verbs work):**
```text
caeruleus shell -b AA:BB:CC:DD:EE:FF
  > primary
  > characteristics
  > char-read-hnd 0x0013          # or: read 0x0013
  > char-write-req 0x0015 41424344
  > listen 0x001e
  > quit
```

**Write a string vs hex (`--req` forces write-with-response):**
```bash
caeruleus write -b AA:BB:CC:DD:EE:FF -a 0x0015 -s "hello"
caeruleus write -b AA:BB:CC:DD:EE:FF -a 0x0015 -n 48656c6c6f --req
```

**Replace those one-off Bleak audit scripts:**
```bash
caeruleus recon -b AA:BB:CC:DD:EE:FF             # fingerprint + hidden-readable chars + DFU/serial audit
caeruleus assess check-auth -b AA:BB:CC:DD:EE:FF # what an unpaired attacker can read (secrets flagged via Titus)
caeruleus assess encryption -b AA:BB:CC:DD:EE:FF # baseline -> pair -> re-test -> unpair fallback
caeruleus assess dfu -b AA:BB:CC:DD:EE:FF        # detect 0xFE59 + unauthenticated buttonless entry
```

**Fuzz a writable characteristic (corpus + crash/hang triage):**
```bash
caeruleus fuzz write -b AA:BB:CC:DD:EE:FF -a 0x0015 --max-time 2m
caeruleus fuzz replay fuzz-out-*/crashes/<id>.bin     # reproduce a crash
```

## The 30-second tour

```
scan        find devices            recon        profile + audit (read-only)
enumerate   browse the GATT tree    assess ...   check-auth | encryption | dfu | wwr
read/write  poke a handle/UUID      pair/unpair  bond / drop bond
listen      capture notifications   fuzz write   fuzz a writable characteristic
shell       interactive REPL        doctor       adapter health + suggested fixes
```

## Scripting

Add `-o json` (or `jsonl`) to any command. Assessment commands emit
`{address, test, summary, findings[]}` with per-finding `severity`, `handle`,
`uuid`, `evidence`. Pipe to `jq`, store per step, and correlate into a report.

```bash
caeruleus assess check-auth -b $A -o json | jq '.findings[] | select(.severity=="high")'
```

## Good to know

- **Connect fails?** Pass `--addr-type random` (or `public`). `scan` shows each device's type.
- **One central at a time:** most peripherals accept a single connection. The tool disconnects on exit; for many back-to-back ops, hold one warm link with `caeruleus serve -b <mac>` + `caeruleus send "read 0x0013"`.
- **Root:** only `conn-params`, `monitor`, `fuzz write --raw`, `cccd --raw`, `raw-write`, `mtu --set`, and `bdaddr --set` need `sudo`.
- **Stuck adapter:** `caeruleus doctor` diagnoses and prints the fix (usually `adapter power cycle` or `forget`).
- **Assessments are non-destructive by default** and exit 0 with findings as data. `assess wwr` and `assess dfu --probe-entry` are the exceptions (they can reset the target).

Full command reference and the recommended assessment methodology:
[`skills/caeruleus/SKILL.md`](../skills/caeruleus/SKILL.md).
