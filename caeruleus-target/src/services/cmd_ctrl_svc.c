/**
 * cmd_ctrl_svc.c — Command & Control Service (0xC0DE)
 *
 * Deliberately vulnerable BLE service for security testing.
 *
 * Vulnerabilities exposed:
 *   1. Command Input   — no sequence number, no nonce → replay attacks
 *   2. Command Response — memcpy without bounds check → buffer overflow / HardFault
 *   3. Admin Control    — open permissions → auth bypass after unpairing
 *
 * nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#include "cmd_ctrl_svc.h"
#include <string.h>
#include "nrf_log.h"
#include "ble_gatts.h"
#include "ble_srv_common.h"

/* --------------------------------------------------------------------------
 * Static buffers — deliberately fixed-size for overflow testing
 * -------------------------------------------------------------------------- */

/** Command Input: stores last received command, no replay protection. */
static uint8_t m_cmd_input_buf[CMD_INPUT_MAX_LEN];
static uint16_t m_cmd_input_len;

/**
 * Command Response buffer — VULNERABILITY:
 * Fixed at 244 bytes.  Writes exceeding this length are memcpy'd without
 * bounds checking, causing a stack/static buffer overflow → HardFault.
 */
static uint8_t m_cmd_response_buf[CMD_RESPONSE_BUF_LEN];

/** Admin state byte — accessible regardless of pairing state. */
static uint8_t m_admin_state;

/** Tracks whether Command Response notifications are enabled via CCCD. */
static bool m_cmd_resp_notif_enabled;

/* ==========================================================================
 * Internal helpers
 * ========================================================================== */

/**
 * @brief Add the Command Input characteristic (UUID 0x0001).
 *
 * Write-only, open permissions, no authentication.
 * Deliberately lacks sequence numbers / nonces — replay-vulnerable.
 */
static uint32_t cmd_input_char_add(ble_cmd_ctrl_svc_t * p_svc)
{
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_t    attr_char_value;
    ble_uuid_t          ble_uuid;
    ble_gatts_attr_md_t attr_md;

    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.write         = 1;
    char_md.char_props.write_wo_resp = 1;
    char_md.p_char_user_desc         = NULL;
    char_md.p_char_pf                = NULL;
    char_md.p_user_desc_md           = NULL;
    char_md.p_cccd_md                = NULL;
    char_md.p_sccd_md                = NULL;

    ble_uuid.type = p_svc->uuid_type;
    ble_uuid.uuid = BLE_CMD_INPUT_CHAR_UUID;

    memset(&attr_md, 0, sizeof(attr_md));
    /* Open permissions — no encryption, no authentication required */
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
    attr_md.vloc = BLE_GATTS_VLOC_STACK;
    attr_md.rd_auth    = 0;
    attr_md.wr_auth    = 0;
    attr_md.vlen       = 1;

    memset(&attr_char_value, 0, sizeof(attr_char_value));
    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = 0;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = CMD_INPUT_MAX_LEN;
    attr_char_value.p_value   = NULL;

    return sd_ble_gatts_characteristic_add(p_svc->service_handle,
                                           &char_md,
                                           &attr_char_value,
                                           &p_svc->cmd_input_handles);
}

/**
 * @brief Add the Command Response characteristic (UUID 0x0002).
 *
 * Read + Notify, open permissions.
 * VULNERABILITY: writes >244 bytes trigger an unsafe memcpy → HardFault.
 * CCCD is added for notification support.
 */
static uint32_t cmd_response_char_add(ble_cmd_ctrl_svc_t * p_svc)
{
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_t    attr_char_value;
    ble_uuid_t          ble_uuid;
    ble_gatts_attr_md_t attr_md;
    ble_gatts_attr_md_t cccd_md;

    /* CCCD metadata — open permissions so any peer can enable notifications */
    memset(&cccd_md, 0, sizeof(cccd_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);
    cccd_md.vloc = BLE_GATTS_VLOC_STACK;

    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.read   = 1;
    char_md.char_props.notify = 1;
    char_md.char_props.write  = 1;  /* Allow writes to trigger the overflow */
    char_md.p_char_user_desc  = NULL;
    char_md.p_char_pf         = NULL;
    char_md.p_user_desc_md    = NULL;
    char_md.p_cccd_md         = &cccd_md;
    char_md.p_sccd_md         = NULL;

    ble_uuid.type = p_svc->uuid_type;
    ble_uuid.uuid = BLE_CMD_RESPONSE_CHAR_UUID;

    memset(&attr_md, 0, sizeof(attr_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
    attr_md.vloc = BLE_GATTS_VLOC_STACK;
    attr_md.rd_auth    = 0;
    attr_md.wr_auth    = 0;
    attr_md.vlen       = 1;

    memset(&attr_char_value, 0, sizeof(attr_char_value));
    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = 0;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = BLE_GATTS_FIX_ATTR_LEN_MAX;  /* SoftDevice max — allows large writes in */
    attr_char_value.p_value   = NULL;

    return sd_ble_gatts_characteristic_add(p_svc->service_handle,
                                           &char_md,
                                           &attr_char_value,
                                           &p_svc->cmd_resp_handles);
}

/**
 * @brief Add the Admin Control characteristic (UUID 0x0003).
 *
 * Read + Write, open permissions — deliberately not gated on connection
 * security.  Accessible even after unpairing → auth bypass vulnerability.
 */
static uint32_t admin_ctrl_char_add(ble_cmd_ctrl_svc_t * p_svc)
{
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_t    attr_char_value;
    ble_uuid_t          ble_uuid;
    ble_gatts_attr_md_t attr_md;

    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.read          = 1;
    char_md.char_props.write         = 1;
    char_md.char_props.write_wo_resp = 1;
    char_md.p_char_user_desc         = NULL;
    char_md.p_char_pf                = NULL;
    char_md.p_user_desc_md           = NULL;
    char_md.p_cccd_md                = NULL;
    char_md.p_sccd_md                = NULL;

    ble_uuid.type = p_svc->uuid_type;
    ble_uuid.uuid = BLE_CMD_ADMIN_CHAR_UUID;

    memset(&attr_md, 0, sizeof(attr_md));
    /* VULNERABILITY: open permissions — no pairing / encryption required.
     * A real service would use BLE_GAP_CONN_SEC_MODE_SET_ENC_WITH_MITM
     * or at minimum BLE_GAP_CONN_SEC_MODE_SET_ENC_NO_MITM.             */
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
    attr_md.vloc = BLE_GATTS_VLOC_STACK;
    attr_md.rd_auth    = 0;
    attr_md.wr_auth    = 0;
    attr_md.vlen       = 0;

    memset(&attr_char_value, 0, sizeof(attr_char_value));
    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = ADMIN_CTRL_LEN;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = ADMIN_CTRL_LEN;
    attr_char_value.p_value   = &m_admin_state;

    return sd_ble_gatts_characteristic_add(p_svc->service_handle,
                                           &char_md,
                                           &attr_char_value,
                                           &p_svc->admin_ctrl_handles);
}

/* ==========================================================================
 * Write-event handlers
 * ========================================================================== */

/**
 * @brief Handle writes to the Command Input characteristic.
 *
 * Accepts any payload, stores it verbatim.  No sequence number, no nonce,
 * no HMAC — an attacker can capture and replay writes freely.
 */
static void on_cmd_input_write(ble_cmd_ctrl_svc_t           * p_svc,
                               ble_gatts_evt_write_t const  * p_evt_write)
{
    uint16_t copy_len = p_evt_write->len;

    if (copy_len > CMD_INPUT_MAX_LEN)
    {
        copy_len = CMD_INPUT_MAX_LEN;
    }

    memcpy(m_cmd_input_buf, p_evt_write->data, copy_len);
    m_cmd_input_len = copy_len;

    NRF_LOG_INFO("[CMD_CTRL] Command Input: %d bytes received (no replay protection)",
                 p_evt_write->len);
    NRF_LOG_HEXDUMP_DEBUG(m_cmd_input_buf, copy_len);
}

/**
 * @brief Handle writes to the Command Response characteristic.
 *
 * VULNERABILITY — BUFFER OVERFLOW:
 * The handler copies the incoming data into a fixed 244-byte buffer using
 * memcpy with the *caller-supplied* length — no bounds check.  A write of
 * >244 bytes will overflow m_cmd_response_buf, corrupt adjacent memory,
 * and trigger a HardFault on Cortex-M4.
 *
 * This is INTENTIONAL for security testing.
 */
static void on_cmd_response_write(ble_cmd_ctrl_svc_t          * p_svc,
                                  ble_gatts_evt_write_t const * p_evt_write)
{
    NRF_LOG_INFO("[CMD_CTRL] Command Response write: %d bytes (buf=%d)",
                 p_evt_write->len, CMD_RESPONSE_BUF_LEN);

    /*
     * DELIBERATE VULNERABILITY — unsafe memcpy:
     *
     *   Buffer size:  CMD_RESPONSE_BUF_LEN (244 bytes)
     *   Copy length:  p_evt_write->len     (attacker-controlled, up to MTU)
     *
     * When p_evt_write->len > 244, this overflows m_cmd_response_buf and
     * corrupts whatever sits after it in the .bss / .data section, leading
     * to a HardFault or potentially arbitrary code execution on a real
     * target.
     */
    memcpy(m_cmd_response_buf, p_evt_write->data, p_evt_write->len);

    NRF_LOG_WARNING("[CMD_CTRL] memcpy completed — %s",
                    (p_evt_write->len > CMD_RESPONSE_BUF_LEN)
                        ? "OVERFLOW — expect HardFault"
                        : "within bounds");
}

/**
 * @brief Handle writes to the Admin Control characteristic.
 *
 * VULNERABILITY — AUTH BYPASS:
 * This handler stores the admin-state byte without checking the connection
 * security level.  Any connected peer — paired or not — can toggle admin
 * state.
 */
static void on_admin_ctrl_write(ble_cmd_ctrl_svc_t          * p_svc,
                                ble_gatts_evt_write_t const * p_evt_write)
{
    if (p_evt_write->len >= ADMIN_CTRL_LEN)
    {
        m_admin_state = p_evt_write->data[0];
        NRF_LOG_INFO("[CMD_CTRL] Admin state set to 0x%02X (no auth check)", m_admin_state);
    }
}

/**
 * @brief Handle CCCD write for Command Response notifications.
 */
static void on_cmd_resp_cccd_write(ble_gatts_evt_write_t const * p_evt_write)
{
    if (p_evt_write->len == 2)
    {
        m_cmd_resp_notif_enabled = ble_srv_is_notification_enabled(p_evt_write->data);
        NRF_LOG_INFO("[CMD_CTRL] Command Response notifications %s",
                     m_cmd_resp_notif_enabled ? "ENABLED" : "DISABLED");
    }
}

/* ==========================================================================
 * BLE event handler
 * ========================================================================== */

void ble_cmd_ctrl_svc_on_ble_evt(ble_evt_t const * p_ble_evt, void * p_context)
{
    ble_cmd_ctrl_svc_t * p_svc = (ble_cmd_ctrl_svc_t *)p_context;

    if (p_svc == NULL || p_ble_evt == NULL)
    {
        return;
    }

    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            p_svc->conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            NRF_LOG_INFO("[CMD_CTRL] Connected, handle=0x%04X", p_svc->conn_handle);
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            NRF_LOG_INFO("[CMD_CTRL] Disconnected, handle=0x%04X", p_svc->conn_handle);
            p_svc->conn_handle       = BLE_CONN_HANDLE_INVALID;
            m_cmd_resp_notif_enabled  = false;
            break;

        case BLE_GATTS_EVT_WRITE:
        {
            ble_gatts_evt_write_t const * p_evt_write =
                &p_ble_evt->evt.gatts_evt.params.write;

            /* Command Input characteristic */
            if (p_evt_write->handle == p_svc->cmd_input_handles.value_handle)
            {
                on_cmd_input_write(p_svc, p_evt_write);
            }
            /* Command Response characteristic */
            else if (p_evt_write->handle == p_svc->cmd_resp_handles.value_handle)
            {
                on_cmd_response_write(p_svc, p_evt_write);
            }
            /* Command Response CCCD */
            else if (p_evt_write->handle == p_svc->cmd_resp_handles.cccd_handle)
            {
                on_cmd_resp_cccd_write(p_evt_write);
            }
            /* Admin Control characteristic */
            else if (p_evt_write->handle == p_svc->admin_ctrl_handles.value_handle)
            {
                on_admin_ctrl_write(p_svc, p_evt_write);
            }
            break;
        }

        default:
            break;
    }
}

/* ==========================================================================
 * Public API
 * ========================================================================== */

uint32_t ble_cmd_ctrl_svc_init(ble_cmd_ctrl_svc_t * p_svc)
{
    uint32_t   err_code;
    ble_uuid_t ble_uuid;

    if (p_svc == NULL)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    /* Zero out context */
    p_svc->conn_handle = BLE_CONN_HANDLE_INVALID;
    m_cmd_resp_notif_enabled = false;
    m_cmd_input_len = 0;
    m_admin_state   = 0;
    memset(m_cmd_input_buf,    0, sizeof(m_cmd_input_buf));
    memset(m_cmd_response_buf, 0, sizeof(m_cmd_response_buf));

    /* Register vendor-specific 128-bit base UUID.
     * This base is DIFFERENT from vuln_data_svc's base UUID. */
    ble_uuid128_t base_uuid = { BLE_CMD_CTRL_BASE_UUID };
    err_code = sd_ble_uuid_vs_add(&base_uuid, &p_svc->uuid_type);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[CMD_CTRL] sd_ble_uuid_vs_add failed: 0x%08X", err_code);
        return err_code;
    }

    /* Add the primary service */
    ble_uuid.type = p_svc->uuid_type;
    ble_uuid.uuid = BLE_CMD_CTRL_SVC_UUID;

    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid,
                                        &p_svc->service_handle);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[CMD_CTRL] Service add failed: 0x%08X", err_code);
        return err_code;
    }

    NRF_LOG_INFO("[CMD_CTRL] Service registered, handle=0x%04X", p_svc->service_handle);

    /* Add characteristics */
    err_code = cmd_input_char_add(p_svc);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[CMD_CTRL] Command Input char add failed: 0x%08X", err_code);
        return err_code;
    }

    err_code = cmd_response_char_add(p_svc);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[CMD_CTRL] Command Response char add failed: 0x%08X", err_code);
        return err_code;
    }

    err_code = admin_ctrl_char_add(p_svc);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[CMD_CTRL] Admin Control char add failed: 0x%08X", err_code);
        return err_code;
    }

    NRF_LOG_INFO("[CMD_CTRL] All characteristics added successfully");
    return NRF_SUCCESS;
}

uint32_t ble_cmd_ctrl_svc_response_notify(ble_cmd_ctrl_svc_t * p_svc,
                                          uint8_t const      * p_data,
                                          uint16_t             length)
{
    if (p_svc == NULL || p_data == NULL)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    if (p_svc->conn_handle == BLE_CONN_HANDLE_INVALID)
    {
        return NRF_ERROR_INVALID_STATE;
    }

    if (!m_cmd_resp_notif_enabled)
    {
        return NRF_ERROR_INVALID_STATE;
    }

    ble_gatts_hvx_params_t hvx_params;
    memset(&hvx_params, 0, sizeof(hvx_params));

    hvx_params.handle = p_svc->cmd_resp_handles.value_handle;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;
    hvx_params.offset = 0;
    hvx_params.p_len  = &length;
    hvx_params.p_data = p_data;

    NRF_LOG_INFO("[CMD_CTRL] Sending notification, %d bytes", length);

    return sd_ble_gatts_hvx(p_svc->conn_handle, &hvx_params);
}

/* --------------------------------------------------------------------------
 * Register BLE observer with SoftDevice handler library
 * -------------------------------------------------------------------------- */
NRF_SDH_BLE_OBSERVER(m_cmd_ctrl_svc_obs,
                      BLE_CMD_CTRL_SVC_BLE_OBSERVER_PRIO,
                      ble_cmd_ctrl_svc_on_ble_evt,
                      NULL);
