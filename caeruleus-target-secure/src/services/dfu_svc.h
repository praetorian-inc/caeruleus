/**
 * dfu_svc.h - Buttonless DFU surface (0xFE59 / 8EC90003)
 *
 * Exposes the Nordic Secure DFU service UUID (0xFE59) with the unbonded
 * buttonless control-point characteristic (8EC90003) in the running
 * application, with OPEN (unauthenticated) write permission.
 *
 * This is intentionally a thin surface, not the full SDK ble_dfu module: a
 * write to the buttonless characteristic sets the bootloader's GPREGRET DFU
 * magic and resets the chip - the real mechanism the SDK uses to enter the
 * bootloader. With the Secure DFU bootloader flashed, that performs a genuine
 * buttonless entry into DFU mode; without it, the device simply resets.
 *
 * It gives caeruleus's `assess dfu` a detectable, unauthenticated buttonless
 * entry point to find (target 1 exposes 0xFE59 only from the bootloader, so
 * `assess dfu` against its application sees nothing).
 *
 * SDK: nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#ifndef DFU_SVC_H
#define DFU_SVC_H

#include <stdint.h>
#include "ble.h"
#include "ble_srv_common.h"
#include "nrf_sdh_ble.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SIG-assigned Secure DFU service UUID (named to avoid clashing with the
 * SDK ble_dfu.h macro of the same purpose, since that include dir is on the
 * build path). */
#define BLE_DFU_SURFACE_SVC_UUID 0xFE59

/* Nordic buttonless DFU (unbonded) base UUID 8EC90000-F315-4F60-9FB8-838830DAEA50,
 * little-endian; bytes 12..13 are the 16-bit slot the SoftDevice fills in. */
#define DFU_BUTTONLESS_UUID_BASE {0x50, 0xEA, 0xDA, 0x30, 0x88, 0x83, \
                                  0xB8, 0x9F, 0x60, 0x4F, 0x15, 0xF3, \
                                  0x00, 0x00, 0xC9, 0x8E}
#define BLE_DFU_BUTTONLESS_CHAR_UUID 0x0003  /**< 8EC90003 buttonless control point. */

typedef struct
{
    uint16_t                 service_handle;
    ble_gatts_char_handles_t buttonless_char_handles;
    uint8_t                  uuid_type;
} ble_dfu_surface_t;

/** Initialise the buttonless DFU surface. */
uint32_t ble_dfu_surface_init(void);

/** BLE event handler; register as an SDH BLE observer. */
void ble_dfu_surface_on_ble_evt(ble_evt_t const *p_ble_evt, void *p_context);

#ifdef __cplusplus
}
#endif

#endif /* DFU_SVC_H */
