/**
 * dfu_public_key.c -- Dummy ECDSA-P256 public key for DFU signature verification
 *
 * !! DELIBERATELY INSECURE -- TEST TARGET ONLY !!
 *
 * This file provides the public key that the Nordic Secure DFU bootloader
 * uses to verify firmware image signatures. In a production bootloader the
 * key would be the raw (uncompressed, no prefix byte) 64-byte P-256 public
 * key corresponding to the private key used by nrfutil to sign DFU packages.
 *
 * Here the key is zeroed out entirely. This is safe to do because:
 *
 *   - NRF_DFU_REQUIRE_SIGNED_APP_UPDATE is set to 0 in sdk_config.h,
 *     so the signature verification code path is never reached.
 *   - NRF_CRYPTO_ENABLED is set to 0 in sdk_config.h, so the crypto
 *     backend that would consume this key is not compiled in.
 *
 * Even if signature verification were somehow enabled at runtime, an
 * all-zero key is not a valid point on the P-256 curve, so verification
 * would fail for every image -- a safe failure mode.
 *
 * The caeruleus test-dfu flow validates that unsigned firmware packages
 * (generated without --key-file) are accepted by this bootloader.
 *
 * SDK:       nRF5 SDK 17.1.0
 * SoftDevice: S140 v7.2.0
 * Target:    nRF52840 DK (PCA10056)
 */

#include <stdint.h>
#include "compiler_abstraction.h"

/**
 * Raw 64-byte ECDSA-P256 public key (x || y, 32 bytes each).
 *
 * All zeros -- no valid signing key exists for this bootloader.
 * This symbol is referenced by the DFU validation module
 * (nrf_dfu_validation.c) but the code path that uses it is
 * compiled out when NRF_DFU_REQUIRE_SIGNED_APP_UPDATE == 0.
 */
__ALIGN(4) const uint8_t pk[64] =
{
    /* x-coordinate (32 bytes) -- zeroed */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    /* y-coordinate (32 bytes) -- zeroed */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
