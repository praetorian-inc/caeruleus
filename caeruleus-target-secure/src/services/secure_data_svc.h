/**
 * secure_data_svc.h - Secure Data Service (0x5EC0)
 *
 * Companion to the Vulnerable Data Service of caeruleus-target, but with the
 * opposite security posture: the sensitive characteristics REQUIRE an
 * encrypted (bonded) link. Reading them on an unpaired link returns an
 * insufficient-authentication error; after Just Works pairing they read back.
 *
 * This lets the caeruleus pair / unpair commands and the assess encryption
 * workflow exercise their enforced-encryption branches (target 1 enforces
 * nothing, so those branches never fire against it).
 *
 * SDK: nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#ifndef SECURE_DATA_SVC_H
#define SECURE_DATA_SVC_H

#include <stdint.h>
#include "ble.h"
#include "ble_srv_common.h"
#include "nrf_sdh_ble.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 128-bit base UUID for the Secure Data Service. The 16-bit field (bytes
 * 12..13 of this little-endian array) is overwritten by the SoftDevice with
 * the per-attribute short UUID, so its value here is a placeholder. */
#define SECURE_DATA_SVC_UUID_BASE {0x00, 0x55, 0x45, 0x4C, 0x55, 0x52, \
                                   0x45, 0x41, 0x43, 0x32, 0x53, 0xC0, \
                                   0x00, 0x00, 0xC0, 0x5E}

#define BLE_SECURE_DATA_SVC_UUID    0x5EC0  /**< Service UUID.                       */
#define BLE_SECURE_SECRET_CHAR_UUID 0x0001  /**< Secret value (enc-required read).   */
#define BLE_SECURE_CONFIG_CHAR_UUID 0x0002  /**< Config blob (enc-required rw).      */
#define BLE_SECURE_INFO_CHAR_UUID   0x0003  /**< Public info (open read, contrast).  */

#define SECURE_DATA_MAX_LEN 64

typedef struct
{
    uint16_t                 service_handle;
    ble_gatts_char_handles_t secret_char_handles;
    ble_gatts_char_handles_t config_char_handles;
    ble_gatts_char_handles_t info_char_handles;
    uint16_t                 conn_handle;
    uint8_t                  uuid_type;
} ble_secure_data_svc_t;

/**
 * @brief Initialise the Secure Data Service.
 *
 * Registers the vendor base UUID, adds the primary service, and adds:
 *   - Secret (0x0001): read, encryption required
 *   - Config (0x0002): read + write, encryption required
 *   - Info   (0x0003): read, open (for contrast in assessments)
 */
uint32_t ble_secure_data_svc_init(void);

/** BLE event handler; register as an SDH BLE observer. */
void ble_secure_data_svc_on_ble_evt(ble_evt_t const *p_ble_evt, void *p_context);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_DATA_SVC_H */
