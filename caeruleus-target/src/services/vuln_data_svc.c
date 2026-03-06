/**
 * vuln_data_svc.c — Vulnerable Data Service (0xBEEF) implementation
 *
 * Deliberately vulnerable BLE service for security testing.
 *
 * Vulnerabilities by design:
 *   - Stored Credential (0x0001): plaintext "admin:password123", open read
 *   - Auth Token      (0x0002): no input validation, arbitrary length write
 *   - Session Key     (0x0003): write-without-response, no rate limiting
 *   - User PII        (0x0004): plaintext PII, open read
 *   - All characteristics: no encryption, no authentication
 *
 * SDK: nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#include "vuln_data_svc.h"

#include <string.h>
#include "app_error.h"
#include "ble_gatts.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

/* =========================================================================
 * Static data
 * ========================================================================= */

/** Service singleton. */
static ble_vuln_data_svc_t m_vuln_data_svc;

/* --- Fixed read-only payloads --- */
static const char m_cred_value[] = "admin:password123";
static const char m_pii_value[]  = "John Doe, john@example.com, 555-0123";

/* --- Writable buffers (no validation, no bounds beyond MTU) --- */
static uint8_t m_token_buf[VULN_DATA_MAX_LEN];
static uint16_t m_token_len;

static uint8_t m_session_buf[VULN_DATA_MAX_LEN];
static uint16_t m_session_len;

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/**
 * @brief Add a read-only characteristic with a fixed initial value.
 */
static uint32_t char_add_readonly(uint16_t           uuid,
                                  uint8_t            uuid_type,
                                  uint16_t           service_handle,
                                  const uint8_t     *p_init_value,
                                  uint16_t           init_len,
                                  uint16_t           max_len,
                                  ble_gatts_char_handles_t *p_handles)
{
    ble_gatts_char_md_t  char_md;
    ble_gatts_attr_t     attr_char_value;
    ble_uuid_t           ble_uuid;
    ble_gatts_attr_md_t  attr_md;

    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.read = 1;

    memset(&attr_md, 0, sizeof(attr_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
    attr_md.vloc = BLE_GATTS_VLOC_STACK;

    ble_uuid.type = uuid_type;
    ble_uuid.uuid = uuid;

    memset(&attr_char_value, 0, sizeof(attr_char_value));
    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = init_len;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = max_len;
    attr_char_value.p_value   = (uint8_t *)p_init_value;

    return sd_ble_gatts_characteristic_add(service_handle,
                                           &char_md,
                                           &attr_char_value,
                                           p_handles);
}

/**
 * @brief Add a read/write characteristic (optionally with write-without-response).
 */
static uint32_t char_add_readwrite(uint16_t           uuid,
                                   uint8_t            uuid_type,
                                   uint16_t           service_handle,
                                   const uint8_t     *p_init_value,
                                   uint16_t           init_len,
                                   uint16_t           max_len,
                                   bool               allow_wwr,
                                   ble_gatts_char_handles_t *p_handles)
{
    ble_gatts_char_md_t  char_md;
    ble_gatts_attr_t     attr_char_value;
    ble_uuid_t           ble_uuid;
    ble_gatts_attr_md_t  attr_md;

    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.read  = 1;
    char_md.char_props.write = 1;
    if (allow_wwr)
    {
        char_md.char_props.write_wo_resp = 1;
    }

    memset(&attr_md, 0, sizeof(attr_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
    attr_md.vloc    = BLE_GATTS_VLOC_STACK;
    attr_md.rd_auth = 0;
    attr_md.wr_auth = 0;

    ble_uuid.type = uuid_type;
    ble_uuid.uuid = uuid;

    memset(&attr_char_value, 0, sizeof(attr_char_value));
    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = init_len;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = max_len;
    attr_char_value.p_value   = (uint8_t *)p_init_value;

    return sd_ble_gatts_characteristic_add(service_handle,
                                           &char_md,
                                           &attr_char_value,
                                           p_handles);
}

/* =========================================================================
 * BLE event handler
 * ========================================================================= */

/**
 * @brief Handle GATTS write events for the Auth Token and Session Key
 *        characteristics.  Stores whatever the central wrote — no validation.
 */
static void on_write(ble_evt_t const *p_ble_evt)
{
    ble_gatts_evt_write_t const *p_evt_write =
        &p_ble_evt->evt.gatts_evt.params.write;

    /* Auth Token characteristic written */
    if (p_evt_write->handle == m_vuln_data_svc.token_char_handles.value_handle)
    {
        uint16_t len = p_evt_write->len;
        if (len > VULN_DATA_MAX_LEN)
        {
            len = VULN_DATA_MAX_LEN;
        }
        memcpy(m_token_buf, p_evt_write->data, len);
        m_token_len = len;

        NRF_LOG_INFO("[VulnData] Auth Token written (%u bytes, NO validation)",
                     p_evt_write->len);
        NRF_LOG_HEXDUMP_DEBUG(m_token_buf, m_token_len);
    }

    /* Session Key characteristic written (write or write-without-response) */
    if (p_evt_write->handle == m_vuln_data_svc.session_char_handles.value_handle)
    {
        uint16_t len = p_evt_write->len;
        if (len > VULN_DATA_MAX_LEN)
        {
            len = VULN_DATA_MAX_LEN;
        }
        memcpy(m_session_buf, p_evt_write->data, len);
        m_session_len = len;

        NRF_LOG_INFO("[VulnData] Session Key written (%u bytes, NO rate limit)",
                     p_evt_write->len);
        NRF_LOG_HEXDUMP_DEBUG(m_session_buf, m_session_len);
    }
}

void ble_vuln_data_svc_on_ble_evt(ble_evt_t const *p_ble_evt, void *p_context)
{
    (void)p_context;

    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            m_vuln_data_svc.conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            NRF_LOG_INFO("[VulnData] Connected (handle 0x%04X)",
                         m_vuln_data_svc.conn_handle);
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            NRF_LOG_INFO("[VulnData] Disconnected (handle 0x%04X)",
                         m_vuln_data_svc.conn_handle);
            m_vuln_data_svc.conn_handle = BLE_CONN_HANDLE_INVALID;
            break;

        case BLE_GATTS_EVT_WRITE:
            on_write(p_ble_evt);
            break;

        default:
            break;
    }
}

/* =========================================================================
 * Initialisation
 * ========================================================================= */

uint32_t ble_vuln_data_svc_init(void)
{
    uint32_t   err_code;
    ble_uuid_t ble_uuid;

    /* ----- Register vendor-specific 128-bit base UUID ----- */
    ble_uuid128_t base_uuid = {VULN_DATA_SVC_UUID_BASE};
    err_code = sd_ble_uuid_vs_add(&base_uuid, &m_vuln_data_svc.uuid_type);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[VulnData] Failed to register base UUID: 0x%08X",
                      err_code);
        return err_code;
    }

    /* ----- Add primary service ----- */
    ble_uuid.type = m_vuln_data_svc.uuid_type;
    ble_uuid.uuid = BLE_VULN_DATA_SVC_UUID;

    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid,
                                        &m_vuln_data_svc.service_handle);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[VulnData] Failed to add service: 0x%08X", err_code);
        return err_code;
    }
    NRF_LOG_INFO("[VulnData] Service registered (handle 0x%04X)",
                 m_vuln_data_svc.service_handle);

    /* ----- Characteristic 1: Stored Credential (read-only) ----- */
    err_code = char_add_readonly(
        BLE_VULN_CRED_CHAR_UUID,
        m_vuln_data_svc.uuid_type,
        m_vuln_data_svc.service_handle,
        (const uint8_t *)m_cred_value,
        sizeof(m_cred_value) - 1,           /* exclude NUL terminator */
        sizeof(m_cred_value) - 1,
        &m_vuln_data_svc.cred_char_handles);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[VulnData] Cred char add failed: 0x%08X", err_code);
        return err_code;
    }
    NRF_LOG_INFO("[VulnData] Stored Credential char added (open read, plaintext)");

    /* ----- Characteristic 2: Auth Token (read + write, no validation) ----- */
    memset(m_token_buf, 0, sizeof(m_token_buf));
    m_token_len = 0;

    err_code = char_add_readwrite(
        BLE_VULN_TOKEN_CHAR_UUID,
        m_vuln_data_svc.uuid_type,
        m_vuln_data_svc.service_handle,
        m_token_buf,
        0,                                  /* initially empty */
        VULN_DATA_MAX_LEN,
        false,                              /* no write-without-response */
        &m_vuln_data_svc.token_char_handles);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[VulnData] Token char add failed: 0x%08X", err_code);
        return err_code;
    }
    NRF_LOG_INFO("[VulnData] Auth Token char added (open rw, no validation)");

    /* ----- Characteristic 3: Session Key (read + write + WWR) ----- */
    memset(m_session_buf, 0, sizeof(m_session_buf));
    m_session_len = 0;

    err_code = char_add_readwrite(
        BLE_VULN_SESSION_CHAR_UUID,
        m_vuln_data_svc.uuid_type,
        m_vuln_data_svc.service_handle,
        m_session_buf,
        0,                                  /* initially empty */
        VULN_DATA_MAX_LEN,
        true,                               /* allow write-without-response */
        &m_vuln_data_svc.session_char_handles);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[VulnData] Session char add failed: 0x%08X", err_code);
        return err_code;
    }
    NRF_LOG_INFO("[VulnData] Session Key char added (open rw + WWR, no rate limit)");

    /* ----- Characteristic 4: User PII (read-only) ----- */
    err_code = char_add_readonly(
        BLE_VULN_PII_CHAR_UUID,
        m_vuln_data_svc.uuid_type,
        m_vuln_data_svc.service_handle,
        (const uint8_t *)m_pii_value,
        sizeof(m_pii_value) - 1,            /* exclude NUL terminator */
        sizeof(m_pii_value) - 1,
        &m_vuln_data_svc.pii_char_handles);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("[VulnData] PII char add failed: 0x%08X", err_code);
        return err_code;
    }
    NRF_LOG_INFO("[VulnData] User PII char added (open read, plaintext)");

    /* ----- Done ----- */
    m_vuln_data_svc.conn_handle = BLE_CONN_HANDLE_INVALID;

    NRF_LOG_INFO("[VulnData] Vulnerable Data Service init complete "
                 "(4 chars, ALL OPEN permissions)");
    return NRF_SUCCESS;
}

/* =========================================================================
 * Accessor
 * ========================================================================= */

ble_vuln_data_svc_t const *ble_vuln_data_svc_get(void)
{
    return &m_vuln_data_svc;
}
