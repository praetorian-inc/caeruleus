# Test DFU Signing Keys

These keys are for testing DFU package signing only. Since the bootloader has
signature verification disabled (`NRF_DFU_REQUIRE_SIGNED_APP_UPDATE=0`), they
are not required for normal operation.

## Generate Keys

```bash
# Generate private key
nrfutil keys generate private.pem

# Extract public key (for dfu_public_key.c if ever needed)
nrfutil keys display --key pk --format code private.pem --out_file public_key.c
```

## Create DFU Packages

```bash
# Unsigned (accepted by vulnerable bootloader)
nrfutil pkg generate --application app.hex \
  --application-version 2 --hw-version 52 \
  --sd-req 0x0100 --no-key unsigned_dfu.zip

# Signed (for comparison testing)
nrfutil pkg generate --application app.hex \
  --application-version 2 --hw-version 52 \
  --sd-req 0x0100 --key-file private.pem signed_dfu.zip

# Downgrade (version 0 — accepted due to no rollback protection)
nrfutil pkg generate --application app.hex \
  --application-version 0 --hw-version 52 \
  --sd-req 0x0100 --no-key downgrade_dfu.zip
```
