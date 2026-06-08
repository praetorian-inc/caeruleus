/**
 * vuln_data_svc.h - Vulnerable Data Service (0xBEEF)
 *
 * Deliberately vulnerable BLE service for security testing.
 * Exposes plaintext credentials, unvalidated token storage,
 * session keys with no rate limiting, and user PII.
 *
 * ALL characteristics use open permissions (no encryption, no auth).
 *
 * SDK: nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#ifndef VULN_DATA_SVC_H
#define VULN_DATA_SVC_H

#include <stdint.h>
#include "ble.h"
#include "ble_srv_common.h"
#include "nrf_sdh_ble.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * UUIDs - from sdk_config.h
 * ------------------------------------------------------------------------- */

/** 128-bit base UUID: XXXXXXXX-CAFE-BABE-DEAD-CAERULEUS00 */
#define VULN_DATA_SVC_UUID_BASE {0x00, 0x55, 0x45, 0x4C, 0x55, 0x52, \
                                 0x45, 0x41, 0x43, 0xAD, 0xDE, 0xBE, \
                                 0xBA, 0xFE, 0xCA, 0x00}

#define BLE_VULN_DATA_SVC_UUID      0xBEEF  /**< Service UUID (slot in base). */
#define BLE_VULN_CRED_CHAR_UUID     0x0001  /**< Stored Credential char.      */
#define BLE_VULN_TOKEN_CHAR_UUID    0x0002  /**< Auth Token char.             */
#define BLE_VULN_SESSION_CHAR_UUID  0x0003  /**< Session Key char.            */
#define BLE_VULN_PII_CHAR_UUID      0x0004  /**< User PII char.              */

/* -------------------------------------------------------------------------
 * Buffer sizes
 * ------------------------------------------------------------------------- */

/** Maximum writable value length (bounded by default ATT MTU). */
#define VULN_DATA_MAX_LEN   244

/* -------------------------------------------------------------------------
 * Service context
 * ------------------------------------------------------------------------- */

/**
 * Vulnerable Data Service structure.
 * Holds GATT handles for the service and its four characteristics.
 */
typedef struct
{
    uint16_t                service_handle;     /**< Service handle (from SoftDevice).   */
    ble_gatts_char_handles_t cred_char_handles;  /**< Stored Credential handles.          */
    ble_gatts_char_handles_t token_char_handles;  /**< Auth Token handles.                 */
    ble_gatts_char_handles_t session_char_handles;/**< Session Key handles.                */
    ble_gatts_char_handles_t pii_char_handles;    /**< User PII handles.                   */
    uint16_t                conn_handle;         /**< Current connection handle.           */
    uint8_t                 uuid_type;           /**< Vendor-specific UUID type.           */
} ble_vuln_data_svc_t;

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/**
 * @brief Initialise the Vulnerable Data Service.
 *
 * Registers the custom 128-bit base UUID, adds the primary service, and
 * adds four characteristics with open (no security) permissions.
 *
 * @return NRF_SUCCESS on success, otherwise an error code from the SoftDevice.
 */
uint32_t ble_vuln_data_svc_init(void);

/**
 * @brief BLE event handler for the Vulnerable Data Service.
 *
 * Call from the BLE observer dispatch. Handles connect, disconnect, and
 * GATTS write events for writable characteristics (Auth Token, Session Key).
 *
 * @param[in] p_ble_evt  Pointer to the BLE event.
 * @param[in] p_context  Unused (may be NULL).
 */
void ble_vuln_data_svc_on_ble_evt(ble_evt_t const *p_ble_evt, void *p_context);

/**
 * @brief Get a pointer to the service context singleton.
 *
 * @return Pointer to the static ble_vuln_data_svc_t instance.
 */
ble_vuln_data_svc_t const *ble_vuln_data_svc_get(void);

#ifdef __cplusplus
}
#endif

#endif /* VULN_DATA_SVC_H */
