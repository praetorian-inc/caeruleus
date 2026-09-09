<!-- Generated from the live cobra command tree by 'make cli-docs'. Do not edit by hand. -->

# caeruleus CLI reference

Every command, alias and flag below is derived from the cobra command tree, not from prose.
Schema version 1, surface hash `sha256:faead0c7394443492ffb96450fc3b2579e7b654de2433c4b2d2125d40d645d2b`.

Regenerate with `make cli-docs` after adding, removing or renaming a command or a flag.

## Command index

| Command | Aliases | Description |
| --- | --- | --- |
| [`caeruleus`](#caeruleus) | *(none)* | BLE GATT toolkit (gatttool/gratttool-style, written in Go) |
| [`caeruleus adapter`](#caeruleus-adapter) | *(none)* | Inspect or recover the local HCI adapter |
| [`caeruleus adapter info`](#caeruleus-adapter-info) | *(none)* | Print adapter info as a single key=value line (--verbose for the multi-line form) |
| [`caeruleus adapter power`](#caeruleus-adapter-power) | *(none)* | Toggle Adapter1.Powered (the equivalent of bluetoothctl 'power on/off') |
| [`caeruleus assess`](#caeruleus-assess) | *(none)* | Active security tests: auth, encryption, pairing, write-without-response, DFU |
| [`caeruleus assess check-auth`](#caeruleus-assess-check-auth) | `auth-bypass` | Read-only by default: what an unpaired attacker can read on -b BDADDR (add --probe-write for write checks) |
| [`caeruleus assess dfu`](#caeruleus-assess-dfu) | *(none)* | Detect a DFU service on -b BDADDR and whether entry is unauthenticated |
| [`caeruleus assess encryption`](#caeruleus-assess-encryption) | *(none)* | Whether pairing changes what -b BDADDR exposes (enforcement / fallback) |
| [`caeruleus assess pairing`](#caeruleus-assess-pairing) | *(none)* | Probe the SMP pairing feature exchange + downgrade resistance (root; takes over the adapter) |
| [`caeruleus assess wwr`](#caeruleus-assess-wwr) | *(none)* | Write-without-response overflow + rapid-fire resilience on -b BDADDR |
| [`caeruleus batch`](#caeruleus-batch) | *(none)* | Run shell commands from stdin against a single persistent connection |
| [`caeruleus bdaddr`](#caeruleus-bdaddr) | *(none)* | Read or spoof the adapter's BD_ADDR (needs root; vendor-specific) |
| [`caeruleus cccd`](#caeruleus-cccd) | *(none)* | Manipulate a Client Characteristic Configuration Descriptor |
| [`caeruleus cccd write`](#caeruleus-cccd-write) | *(none)* | Write a 2-byte CCCD value via BlueZ (or raw L2CAP if --raw) |
| [`caeruleus characteristics`](#caeruleus-characteristics) | `chars` | List characteristics (gatttool --characteristics) |
| [`caeruleus completion`](#caeruleus-completion) | *(none)* | Generate a shell completion script |
| [`caeruleus conn-params`](#caeruleus-conn-params) | `connparams`, `cparams` | Report the negotiated connection parameters for -b BDADDR (needs root) |
| [`caeruleus disconnect`](#caeruleus-disconnect) | `dc` | Disconnect a peripheral and wait for Connected=false |
| [`caeruleus doctor`](#caeruleus-doctor) | *(none)* | One-shot adapter / bluetoothd health summary with suggested fixes |
| [`caeruleus enumerate`](#caeruleus-enumerate) | `enum` | Print a device's full GATT tree as a table (--values also reads each characteristic) |
| [`caeruleus forget`](#caeruleus-forget) | `rm`, `remove` | Tell bluetoothd to purge cached state for -b BDADDR |
| [`caeruleus fuzz`](#caeruleus-fuzz) | *(none)* | Fuzz a GATT server (mutates writes, classifies responses) |
| [`caeruleus fuzz replay`](#caeruleus-fuzz-replay) | *(none)* | Re-send inputs from a saved corpus file or directory |
| [`caeruleus fuzz write`](#caeruleus-fuzz-write) | *(none)* | Fuzz writes to a single characteristic |
| [`caeruleus listen`](#caeruleus-listen) | `notify`, `subscribe` | Subscribe to notifications/indications on a characteristic |
| [`caeruleus monitor`](#caeruleus-monitor) | *(none)* | Passively decode ATT notifications/indications from the HCI monitor socket (needs root) |
| [`caeruleus mtu`](#caeruleus-mtu) | *(none)* | Read or set the requested ATT MTU (set/reset require root + bluetoothd restart) |
| [`caeruleus pair`](#caeruleus-pair) | *(none)* | Pair / bond with -b BDADDR (BlueZ Device1.Pair) |
| [`caeruleus primary`](#caeruleus-primary) | *(none)* | List primary services (gatttool --primary) |
| [`caeruleus raw-write`](#caeruleus-raw-write) | *(none)* | Single-PDU ATT Write Request via raw L2CAP (bypasses BlueZ MTU + fragmentation) |
| [`caeruleus read`](#caeruleus-read) | `char-read` | Read a characteristic by handle (-a) or UUID (-u) |
| [`caeruleus recipes`](#caeruleus-recipes) | *(none)* | Find the right command by describing what you want to do |
| [`caeruleus recon`](#caeruleus-recon) | *(none)* | Profile -b BDADDR: fingerprint (DIS), service map, and GATT audit |
| [`caeruleus scan`](#caeruleus-scan) | *(none)* | Scan for nearby BLE devices |
| [`caeruleus send`](#caeruleus-send) | *(none)* | Send one shell command to a running 'caeruleus serve' daemon |
| [`caeruleus serve`](#caeruleus-serve) | *(none)* | Run a long-lived daemon holding one GATT link; clients dispatch over a Unix socket |
| [`caeruleus shell`](#caeruleus-shell) | `interactive` | Open an interactive readline shell against a device |
| [`caeruleus unpair`](#caeruleus-unpair) | *(none)* | Drop the bond / pairing for -b BDADDR (BlueZ Adapter1.RemoveDevice) |
| [`caeruleus write`](#caeruleus-write) | `char-write` | Write a value to a characteristic by handle (-a) or UUID (-u) |

## `caeruleus`

BLE GATT toolkit (gatttool/gratttool-style, written in Go)

- Usage: `caeruleus`
- Aliases: *(none)*
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus adapter`

Inspect or recover the local HCI adapter

- Usage: `caeruleus adapter`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus adapter info`

Print adapter info as a single key=value line (--verbose for the multi-line form)

- Usage: `caeruleus adapter info`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--verbose` |  | bool | `false` | print one labelled line per field (slower to scan, easier to read) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |

## `caeruleus adapter power`

Toggle Adapter1.Powered (the equivalent of bluetoothctl 'power on/off')

- Usage: `caeruleus adapter power [on|off|cycle]`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus assess`

Active security tests: auth, encryption, pairing, write-without-response, DFU

- Usage: `caeruleus assess`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus assess check-auth`

Read-only by default: what an unpaired attacker can read on -b BDADDR (add --probe-write for write checks)

- Usage: `caeruleus assess check-auth`
- Aliases: `auth-bypass`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--probe-write` |  | bool | `false` | also test writes by writing each readable value back to itself (opt-in; exercises the write path) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus assess dfu`

Detect a DFU service on -b BDADDR and whether entry is unauthenticated

- Usage: `caeruleus assess dfu`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--probe-entry` |  | bool | `false` | actually write the buttonless enter-DFU opcode (DESTRUCTIVE: reboots the device) |
| `--yes` | `-y` | bool | `false` | skip the confirmation prompt for --probe-entry |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus assess encryption`

Whether pairing changes what -b BDADDR exposes (enforcement / fallback)

- Usage: `caeruleus assess encryption`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus assess pairing`

Probe the SMP pairing feature exchange + downgrade resistance (root; takes over the adapter)

- Usage: `caeruleus assess pairing`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus assess wwr`

Write-without-response overflow + rapid-fire resilience on -b BDADDR

- Usage: `caeruleus assess wwr`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--burst` |  | int | `100` | number of rapid-fire writes for the exhaustion test |
| `--sizes` |  | intSlice | `[20,50,100,200,512]` | payload sizes (bytes) for the overflow sweep |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus batch`

Run shell commands from stdin against a single persistent connection

- Usage: `caeruleus batch`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus bdaddr`

Read or spoof the adapter's BD_ADDR (needs root; vendor-specific)

- Usage: `caeruleus bdaddr`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--list-vendors` |  | bool | `false` | list known vendor command tables and exit |
| `--no-apply` |  | bool | `false` | no-op; the apply step is off by default now (hidden) |
| `--no-reset` |  | bool | `false` | deprecated alias for --no-apply (no-op) (hidden) |
| `--refresh-bluez` |  | bool | `false` | LAST RESORT only - use plain --set first. Runs HCIDEVRESET after the vendor write; on some chips (notably Intel AX) this also reloads OTP and silently reverts the spoof, and can leave the controller stuck in BR/EDR INQUIRY mode. Reach for this only when plain --set leaves bluetoothd reporting the old addr. |
| `--set` |  | string |  | rewrite the adapter BD_ADDR to this MAC |
| `--show` |  | bool | `false` | read and print the current adapter BD_ADDR + manufacturer |
| `--transient` |  | bool | `false` | do not persist the change (informational only - kernel decides) |
| `--vendor` |  | string |  | force a specific vendor command (csr\|broadcom\|ti\|intel\|zeevo\|st\|cypress\|ericsson) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus cccd`

Manipulate a Client Characteristic Configuration Descriptor

- Usage: `caeruleus cccd`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus cccd write`

Write a 2-byte CCCD value via BlueZ (or raw L2CAP if --raw)

- Usage: `caeruleus cccd write`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--char` |  | string |  | characteristic value handle; CCCD is auto-located on that char |
| `--enable` |  | string |  | notify \| indicate \| off |
| `--handle` |  | string |  | explicit descriptor handle to write to (skips auto-discovery) |
| `--raw` |  | bool | `false` | use raw L2CAP ATT path (Layer B - requires root and --handle) |
| `--value` |  | string |  | explicit 2-byte hex value (overrides --enable) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus characteristics`

List characteristics (gatttool --characteristics)

- Usage: `caeruleus characteristics`
- Aliases: `chars`

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus completion`

Generate a shell completion script

- Usage: `caeruleus completion [bash|zsh|fish|powershell]`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus conn-params`

Report the negotiated connection parameters for -b BDADDR (needs root)

- Usage: `caeruleus conn-params`
- Aliases: `connparams`, `cparams`

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus disconnect`

Disconnect a peripheral and wait for Connected=false

- Usage: `caeruleus disconnect`
- Aliases: `dc`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--wait` |  | int | `3` | seconds to wait for Connected=false |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus doctor`

One-shot adapter / bluetoothd health summary with suggested fixes

- Usage: `caeruleus doctor`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus enumerate`

Print a device's full GATT tree as a table (--values also reads each characteristic)

- Usage: `caeruleus enumerate`
- Aliases: `enum`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--compact` |  | bool | `false` | emit one key=value line per characteristic instead of the wide table (token-efficient for scripts / LLMs) |
| `--max-len` |  | int | `64` | truncate displayed values to this many bytes |
| `--raw` |  | bool | `false` | discover the GATT DB directly over raw ATT (host/BlueZ-independent; TRUE handles, incl. GAP/GATT services BlueZ may hide); needs root |
| `--values` |  | bool | `false` | read each readable characteristic and include its value (slow; opt in only) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus forget`

Tell bluetoothd to purge cached state for -b BDADDR

- Usage: `caeruleus forget`
- Aliases: `rm`, `remove`

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus fuzz`

Fuzz a GATT server (mutates writes, classifies responses)

- Usage: `caeruleus fuzz`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus fuzz replay`

Re-send inputs from a saved corpus file or directory

- Usage: `caeruleus fuzz replay PATH`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--handle` | `-a` | string |  | target characteristic/descriptor handle |
| `--op` |  | string | `req` | write variant for replay: req \| cmd |
| `--uuid` | `-u` | string |  | target characteristic UUID (alternative to --handle) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus fuzz write`

Fuzz writes to a single characteristic

- Usage: `caeruleus fuzz write`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--handle` | `-a` | string |  | target characteristic/descriptor handle |
| `--include` |  | string |  | extra opcodes to enable, comma-separated: prep, exec (implies --raw) |
| `--liveness-every` |  | int | `10` | probe target liveness every N iterations |
| `--liveness-handle` |  | string |  | override auto-detected liveness handle |
| `--max-iter` |  | int | `10000` | iteration cap (0 = unlimited) |
| `--max-time` |  | duration | `0s` | wall-clock cap (e.g. 30m, 8h) |
| `--max-value-len` |  | int | `244` | hard cap on mutated input length (244 = MTU 247 - 3 ATT bytes) |
| `--no-boundary-seeds` |  | bool | `false` | in --raw mode, skip the auto-added MTU-boundary length seeds |
| `--no-liveness` |  | bool | `false` | disable liveness probing entirely (disconnect is the only crash signal) |
| `--no-seed` |  | bool | `false` | skip auto-read; start from an empty seed |
| `--no-state-feedback` |  | bool | `false` | treat every input as parentless; disable input prioritisation |
| `--out` |  | string |  | corpus output directory (default ./fuzz-out-&lt;ISO&gt;/) |
| `--raw` |  | bool | `false` | drive writes via raw L2CAP/ATT (Layer B) instead of BlueZ D-Bus; required for prep/exec |
| `--rng-seed` |  | int64 | `0` | RNG seed (default: time-based; printed at startup) |
| `--seed` |  | string |  | ASCII seed (alternative to --seed-file) |
| `--seed-dir` |  | string |  | directory of seed files; all .bin are loaded |
| `--seed-file` |  | string |  | raw seed file (overrides auto-read) |
| `--target-reset` |  | string |  | shell command to reset the target after consecutive liveness failures |
| `--target-reset-after` |  | int | `3` | fire --target-reset after this many consecutive liveness failures |
| `--type` |  | string | `req` | write variant(s): req \| cmd \| both |
| `--uuid` | `-u` | string |  | target characteristic UUID (alternative to --handle) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus listen`

Subscribe to notifications/indications on a characteristic

- Usage: `caeruleus listen`
- Aliases: `notify`, `subscribe`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--count` |  | int | `0` | stop after receiving this many notifications (0 = unlimited; auto-set to 1 when --trigger-value is given and --count isn't) |
| `--duration` | `-d` | int | `5` | stop after this many seconds (0 = forever) |
| `--extract` |  | bool | `false` | print just the hex payload per event (lossless, one line each) - pipe to `write -n` |
| `--handle` | `-a` | string |  | ATT handle of the characteristic |
| `--hidden` |  | bool | `false` | don't call StartNotify - only watch via HCI monitor (for chars that don't advertise notify; needs --monitor on) |
| `--monitor` |  | string | `auto` | fan in HCI monitor socket events too: auto\|on\|off (auto = on if euid==0) |
| `--retry` |  | int | `0` | retry the entire listen window up to N times on transient BlueZ/HCI errors |
| `--retry-delay` |  | duration | `500ms` | delay between retries |
| `--trigger-count` |  | int | `1` | number of times to fire --trigger-value (use with --count 0 to capture every response) |
| `--trigger-handle` |  | string |  | handle to write the trigger value to (defaults to the listen handle) |
| `--trigger-interval` |  | duration | `300ms` | delay between repeated triggers |
| `--trigger-value` |  | string |  | hex value to write before listening (forces a notify); pairs with --trigger-count for repeated fires |
| `--uuid` | `-u` | string |  | characteristic UUID |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus monitor`

Passively decode ATT notifications/indications from the HCI monitor socket (needs root)

- Usage: `caeruleus monitor`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--count` |  | int | `0` | stop after receiving this many events (0 = no limit) |
| `--duration` | `-d` | int | `10` | stop after this many seconds (0 = forever) |
| `--extract` |  | bool | `false` | print just the hex payload per event (one line each) - parity with listen --extract |
| `--handle` | `-a` | string |  | only print events whose PDU att-handle matches (NOT the subscribed char - drop the filter first if unsure) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus mtu`

Read or set the requested ATT MTU (set/reset require root + bluetoothd restart)

- Usage: `caeruleus mtu`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--conf-dir` |  | string | `/etc/bluetooth` | bluetooth config directory |
| `--dry-run` |  | bool | `false` | print the planned edit without writing or restarting |
| `--force` |  | bool | `false` | accept --set values outside the safe band without prompting |
| `--no-wait` |  | bool | `false` | do not wait for bluetoothd to come back up after restart |
| `--reset` |  | bool | `false` | restore ExchangeMTU to a safe interoperable default (247). Combine with --to-spec-default for 517. PROMPTS on TTY; pair with -y for scripts. |
| `--revert` |  | bool | `false` | restore the value snapshotted before the last --set/--reset |
| `--set` |  | int | `0` | request this ATT MTU on the next connection (23..517). PROMPTS on TTY; pair with -y for scripts. |
| `--show` |  | bool | `false` | show the current connection's negotiated MTU |
| `--to-spec-default` |  | bool | `false` | with --reset, write 517 (BLE spec max) instead of the interoperable default (247) |
| `--yes` | `-y` | bool | `false` | skip the disruptive-op confirmation prompt |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus pair`

Pair / bond with -b BDADDR (BlueZ Device1.Pair)

- Usage: `caeruleus pair`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--io` |  | string | `none` | IO capability: none\|display-only\|keyboard-only\|display-yesno\|keyboard-display |
| `--oob` |  | string |  | OOB secret as hex: 32 chars (legacy TK) or confirm:random (SC, 32:32 chars) |
| `--pair-mode` |  | string | `auto` | pairing strategy: send-pairing\|receive-pairing\|auto |
| `--passkey` |  | string |  | passkey for Passkey Entry: digits, or '-' to prompt interactively |
| `--rebond` |  | bool | `false` | drop any existing bond first, then pair fresh |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus primary`

List primary services (gatttool --primary)

- Usage: `caeruleus primary`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus raw-write`

Single-PDU ATT Write Request via raw L2CAP (bypasses BlueZ MTU + fragmentation)

- Usage: `caeruleus raw-write`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--handle` | `-a` | string |  | target ATT handle (e.g. 0x001e) |
| `--length` |  | int | `0` | value length when using --pattern |
| `--pattern` |  | string | `0x41` | byte pattern to fill --length bytes (default 0x41 'A') |
| `--value` | `-n` | string |  | explicit hex value (overrides --length/--pattern) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus read`

Read a characteristic by handle (-a) or UUID (-u)

- Usage: `caeruleus read`
- Aliases: `char-read`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--ascii` | `-A` | bool | `false` | print just the decoded ASCII payload, no key=value framing |
| `--changes-only` |  | bool | `false` | during --watch, only print when the value differs from the previous read |
| `--duration` |  | duration | `0s` | stop --watch after this duration (0 = until SIGINT) |
| `--every` |  | duration | `100ms` | watch poll interval |
| `--extract` |  | bool | `false` | print just the hex payload (lossless, single line) - pipe to `write -n` for round-trip |
| `--handle` | `-a` | string |  | ATT handle (e.g. 0x002a) |
| `--offset` |  | uint16 | `0` | read offset (for long reads) |
| `--raw` |  | bool | `false` | read the exact handle over raw ATT (root), bypassing BlueZ - reaches handles BlueZ doesn't expose (e.g. hidden GAP service chars on older BlueZ); pair with `enumerate --raw` |
| `--retry` |  | int | `0` | retry up to N times when the operation fails with a transient BlueZ/HCI error |
| `--retry-delay` |  | duration | `500ms` | delay between retries (e.g. 250ms, 2s) |
| `--uuid` | `-u` | string |  | characteristic UUID |
| `--watch` |  | bool | `false` | keep re-reading until SIGINT or --duration expires |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus recipes`

Find the right command by describing what you want to do

- Usage: `caeruleus recipes [search term]`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus recon`

Profile -b BDADDR: fingerprint (DIS), service map, and GATT audit

- Usage: `caeruleus recon`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus scan`

Scan for nearby BLE devices

- Usage: `caeruleus scan`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--duration` | `-d` | int | `8` | scan duration in seconds |
| `--include-cached` |  | bool | `false` | also show devices BlueZ cached from previous scans, not just those actively advertising |
| `--keep-filter` |  | bool | `false` | leave the DiscoveryFilter in place after scan returns (default: clear it) |
| `--live` |  | bool | `false` | stream devices as they are discovered/updated instead of printing one table at the end |
| `--name` |  | string |  | only print devices whose name matches this substring |
| `--prefix` |  | string |  | only print devices whose address starts with this prefix |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus send`

Send one shell command to a running 'caeruleus serve' daemon

- Usage: `caeruleus send`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--socket` |  | string |  | Unix socket path (default: $CAERULEUS_SOCK or ~/.cache/caeruleus/serve.sock) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus serve`

Run a long-lived daemon holding one GATT link; clients dispatch over a Unix socket

- Usage: `caeruleus serve`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--socket` |  | string | `/root/.cache/caeruleus/serve.sock` | Unix socket path to listen on |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus shell`

Open an interactive readline shell against a device

- Usage: `caeruleus shell`
- Aliases: `interactive`

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus unpair`

Drop the bond / pairing for -b BDADDR (BlueZ Adapter1.RemoveDevice)

- Usage: `caeruleus unpair`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |

## `caeruleus write`

Write a value to a characteristic by handle (-a) or UUID (-u)

- Usage: `caeruleus write`
- Aliases: `char-write`

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--each-line` |  | bool | `false` | read stdin one ASCII payload per line and write each to --handle |
| `--handle` | `-a` | string |  | ATT handle (e.g. 0x002c) |
| `--req` |  | bool | `false` | use write-with-response (write request) instead of write-command |
| `--retry` |  | int | `0` | retry up to N times when the operation fails with a transient BlueZ/HCI error |
| `--retry-delay` |  | duration | `500ms` | delay between retries |
| `--string` | `-s` | string |  | ASCII string to write (alternative to -n) |
| `--uuid` | `-u` | string |  | characteristic UUID |
| `--value` | `-n` | string |  | hex value to write (e.g. deadbeef) |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--adapter` | `-i` | string | `hci0` | HCI adapter name (e.g. hci0) |
| `--addr-type` |  | string |  | address type: public \| random (auto if blank) |
| `--bdaddr` | `-b` | string |  | remote BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `--format` | `-o` | string | `text` | output format: text \| json \| jsonl (json/jsonl output is authoritative; do not re-run in text mode) |
| `--json` |  | bool | `false` | deprecated alias for --format jsonl (hidden) |
| `--quiet` | `-q` | bool | `false` | suppress informational status lines on stderr (data + errors still emitted) |
| `--timeout` | `-t` | int | `45` | operation timeout, seconds |
| `--verbose` | `-v` | bool | `false` | verbose diagnostic logging on stderr |
