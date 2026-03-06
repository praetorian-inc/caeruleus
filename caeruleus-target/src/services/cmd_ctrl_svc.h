/**
 * cmd_ctrl_svc.h — Command & Control Service (0xC0DE)
 *
 * Deliberately vulnerable BLE service for security testing.
 *
 * Vulnerabilities:
 *   - Command Input:    No sequence number / nonce — replay-vulnerable
 *   - Command Response: Buffer overflow on writes >244 bytes → HardFault
 *   - Admin Control:    Auth bypass — accessible without pairing
 *
 * Service UUID:  C0DE???? -7890-ABCD-EF01-223344556677  (base)
 *                         short = 0xC0DE
 *
 * nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#ifndef CMD_CTRL_SVC_H__
#define CMD_CTRL_SVC_H__

#include <stdint.h>
#include <stdbool.h>
#include "ble.h"
#include "ble_srv_common.h"
#include "nrf_sdh_ble.h"
#include "sdk_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Observer priority — register with the SoftDevice BLE event dispatcher
 * -------------------------------------------------------------------------- */
#define BLE_CMD_CTRL_SVC_BLE_OBSERVER_PRIO  2

/* Forward declaration */
typedef struct ble_cmd_ctrl_svc_s ble_cmd_ctrl_svc_t;

/* --------------------------------------------------------------------------
 * 128-bit base UUID for Command & Control Service
 *
 * Base: xx007890-ABCD-EF01-2233-44556677AABB
 *   where xx is replaced by the 16-bit short UUID via sd_ble_uuid_vs_add.
 *
 * This is intentionally DIFFERENT from vuln_data_svc's base UUID.
 * -------------------------------------------------------------------------- */
#define BLE_CMD_CTRL_BASE_UUID  { 0xBB, 0xAA, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, \
                                  0x01, 0xEF, 0xCD, 0xAB, 0x00, 0x00, 0x90, 0x78 }

/* --------------------------------------------------------------------------
 * Characteristic buffer sizes
 * -------------------------------------------------------------------------- */
#define CMD_INPUT_MAX_LEN       244     /**< Max command input length.        */
#define CMD_RESPONSE_BUF_LEN    244     /**< Fixed response buffer — overflow
                                             target when write exceeds this.  */
#define ADMIN_CTRL_LEN          1       /**< Single admin-state byte.         */

/* --------------------------------------------------------------------------
 * Service context structure
 * -------------------------------------------------------------------------- */
struct ble_cmd_ctrl_svc_s
{
    uint16_t                    service_handle;     /**< Service handle (SoftDevice).       */
    ble_gatts_char_handles_t    cmd_input_handles;  /**< Command Input char handles.        */
    ble_gatts_char_handles_t    cmd_resp_handles;   /**< Command Response char handles.     */
    ble_gatts_char_handles_t    admin_ctrl_handles; /**< Admin Control char handles.        */
    uint16_t                    conn_handle;        /**< Current connection handle.         */
    uint8_t                     uuid_type;          /**< Vendor-specific UUID type index.   */
};

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

/**
 * @brief Initialise the Command & Control Service.
 *
 * Registers the vendor-specific base UUID, adds the service and its three
 * characteristics to the SoftDevice GATT table.
 *
 * @param[in,out] p_svc  Pointer to service context (must persist for the
 *                        lifetime of the application).
 *
 * @retval NRF_SUCCESS           On success.
 * @retval NRF_ERROR_INVALID_PARAM  If p_svc is NULL.
 * @retval Other                 Propagated SoftDevice error codes.
 */
uint32_t ble_cmd_ctrl_svc_init(ble_cmd_ctrl_svc_t * p_svc);

/**
 * @brief BLE event handler — forward SoftDevice events to this service.
 *
 * Must be called from the BLE event dispatcher (registered via
 * NRF_SDH_BLE_OBSERVER).  Handles connect, disconnect, and GATTS write
 * events for the three characteristics.
 *
 * @param[in] p_ble_evt  Pointer to the BLE event.
 * @param[in] p_context  Pointer to the service context.
 */
void ble_cmd_ctrl_svc_on_ble_evt(ble_evt_t const * p_ble_evt, void * p_context);

/**
 * @brief Send a notification on the Command Response characteristic.
 *
 * @param[in] p_svc   Pointer to service context.
 * @param[in] p_data  Data to notify.
 * @param[in] length  Length of p_data (max CMD_RESPONSE_BUF_LEN).
 *
 * @retval NRF_SUCCESS           On success.
 * @retval NRF_ERROR_INVALID_STATE  If notifications not enabled or not connected.
 * @retval Other                 Propagated SoftDevice error codes.
 */
uint32_t ble_cmd_ctrl_svc_response_notify(ble_cmd_ctrl_svc_t * p_svc,
                                          uint8_t const      * p_data,
                                          uint16_t             length);

#ifdef __cplusplus
}
#endif

#endif /* CMD_CTRL_SVC_H__ */
