# Caeruleus-Secure

A second deliberately-built nRF52840 target, the security-enforcing counterpart to [`caeruleus-target`](../caeruleus-target/). Where target 1 enforces nothing, this one:

- **bonds** via Just Works pairing and marks its sensitive characteristics **encryption-required**, so they read only over a paired link; and
- exposes an **unauthenticated buttonless DFU** surface (`0xFE59` / `8EC90003`) in the running application.

It exists to exercise the caeruleus `pair` / `unpair` commands, the `assess encryption` workflow (enforcement + post-unpair fallback branches), and `assess dfu` (which sees nothing against target 1, whose DFU lives only in the bootloader).

**Hardware:** nRF52840 DK (PCA10056)
**SDK:** nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0

> Authored against the same SDK setup as target 1; not compiled in this repo (no toolchain here). Build on your own nRF5 SDK install. If the first build surfaces an SDK-version detail, send the error and it is a quick fix.

## GATT profile

| Service | UUID | Characteristic | UUID | Access |
|---|---|---|---|---|
| Device Information | `0x180A` | Manufacturer / FW / HW rev | std | open read (fingerprinting) |
| Secure Data | `0x5EC0` | Secret | `0x0001` | **read, encryption required** |
| | | Config | `0x0002` | **read+write, encryption required** |
| | | Info | `0x0003` | open read (contrast) |
| Buttonless DFU | `0xFE59` | Buttonless control point | `8EC90003` | **write, open (unauthenticated)** |

## Security configuration

- **Pairing:** Just Works, bonding on, no MITM/passkey (`bond=1, mitm=0, lesc=0, io_caps=NONE`) so an agent-less central (caeruleus / BlueZ) can complete pairing.
- **Encryption:** required (`SEC_MODE` enc, no MITM) on the Secret and Config characteristics; reading them unpaired returns insufficient-authentication, which caeruleus classifies as auth-required.
- **DFU entry:** the buttonless write sets the bootloader GPREGRET DFU magic (`0xB1`) and resets the chip - the real mechanism the SDK uses to enter the bootloader. With the Secure DFU bootloader flashed it performs a genuine buttonless entry; without it the device just resets. The write permission is open, so the entry is unauthenticated by design.

## Build and flash

Same toolchain as target 1 (ARM GCC, nRF Command Line Tools, SoftDevice S140). With one board, reflash between targets.

```bash
export SDK_ROOT=/path/to/nRF5_SDK_17.1.0_ddde560

# 1. SoftDevice (one-time; already present if target 1 was flashed)
nrfjprog --program $SDK_ROOT/components/softdevice/s140/hex/s140_nrf52_7.2.0_softdevice.hex \
  --chiperase -f nrf52
nrfjprog --reset -f nrf52

# 2. Build + flash this application
cd pca10056/s140/armgcc
make
nrfjprog --program _build/nrf52840_xxaa.hex --sectorerase -f nrf52
nrfjprog --reset -f nrf52
```

To swap back to target 1, rebuild and flash from `../caeruleus-target/pca10056/s140/armgcc`.

For a real buttonless-DFU entry (not just a reset), flash the Secure DFU bootloader and signing key from `../caeruleus-target/dfu` and `../caeruleus-target/keys`; otherwise the buttonless write simply resets the device, which is enough for `assess dfu` to detect and report the entry point.

## Validating with caeruleus

```bash
A=<bdaddr of Caeruleus-Secure>     # from: ./caeruleus scan ; it advertises as "Caeruleus-Secure"

# Recon: should show the DFU service (0xFE59) and a hidden/encrypted Secret char.
./caeruleus recon -b $A -o json

# Unpaired exposure: Info reads; Secret/Config report auth-required.
./caeruleus assess auth-bypass -b $A

# Pairing: Just Works bond should complete.
./caeruleus pair -b $A           # expect paired=true bonded=true
# Now the Secret characteristic reads back over the encrypted link:
./caeruleus read -b $A -u 00005ec0...0001   # or use the handle from recon

# Encryption enforcement: baseline -> pair -> re-test -> unpair fallback.
./caeruleus assess encryption -b $A

# Drop the bond again:
./caeruleus unpair -b $A

# DFU: detects 0xFE59 + the unauthenticated buttonless entry (HIGH).
./caeruleus assess dfu -b $A
# Optional, destructive (resets / enters bootloader):
./caeruleus assess dfu -b $A --probe-entry -y
```

## Upgrading to LE Secure Connections (LESC)

This target ships with legacy Just Works to keep the build identical to target 1's proven configuration. To switch to LESC pairing:

1. `config/sdk_config.h`: set `SEC_PARAM_LESC 1` (and keep `SEC_PARAM_MITM 0` for Just-Works-style LESC).
2. Add the LESC + crypto sources to the Makefile `SRC_FILES`: `nrf_ble_lesc.c` and the `nrf_crypto` backend (CC310 on the nRF52840), and enable `NRF_CRYPTO_BACKEND_CC310_ENABLED` in `sdk_config.h`.
3. In `main.c`: call `nrf_ble_lesc_init()` after the BLE stack init and `nrf_ble_lesc_request_handler()` from the main loop, and generate the LESC keypair on `PM_EVT_CONN_SEC_PARAMS_REQ` (see the SDK `ble_app_*` LESC examples).

The caeruleus-side behaviour (pair completes and bonds, encryption enforced, fallback after unpair) is the same either way.
