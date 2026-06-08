/**
 * secure_data_svc.c - Secure Data Service (0x5EC0) implementation
 *
 * Security posture (the point of this target):
 *   - Secret (0x0001): read requires an encrypted link (SEC_MODE ENC_NO_MITM)
 *   - Config (0x0002): read + write require an encrypted link
 *   - Info   (0x0003): open read, so an unpaired peer still sees something
 *
 * On an unpaired link the SoftDevice answers reads of Secret/Config with
 * BLE_GATT_STATUS_ATTERR_INSUF_AUTHENTICATION, which BlueZ surfaces as an
 * authentication error - caeruleus classifies that as auth-required. After
 * Just Works bonding the same reads succeed.
 *
 * SDK: nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#include "secure_data_svc.h"

#include <string.h>
#include "ble_gatts.h"
#include "nrf_log.h"

static ble_secure_data_svc_t m_svc;

static const char m_secret_value[] = "TOP-SECRET-KEY-2.0";
static const char m_info_value[]   = "Caeruleus secure target; pair to read protected data";

static uint8_t  m_config_buf[SECURE_DATA_MAX_LEN];
static uint16_t m_config_len;

/* read_enc / write_enc select per-attribute security: when true the attribute
 * requires an encrypted link; when false it is open. */
static uint32_t char_add(uint16_t                   uuid,
                         uint8_t                    uuid_type,
                         uint16_t                   service_handle,
                         const uint8_t             *p_init_value,
                         uint16_t                   init_len,
                         uint16_t                   max_len,
                         bool                       writable,
                         bool                       enc_required,
                         ble_gatts_char_handles_t  *p_handles)
{
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_t    attr_char_value;
    ble_uuid_t          ble_uuid;
    ble_gatts_attr_md_t attr_md;

    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.read = 1;
    if (writable)
    {
        char_md.char_props.write = 1;
    }

    memset(&attr_md, 0, sizeof(attr_md));
    if (enc_required)
    {
        /* Encrypted link required, no MITM (matches Just Works bonding). */
        BLE_GAP_CONN_SEC_MODE_SET_ENC_NO_MITM(&attr_md.read_perm);
        if (writable)
        {
            BLE_GAP_CONN_SEC_MODE_SET_ENC_NO_MITM(&attr_md.write_perm);
        }
        else
        {
            BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
        }
    }
    else
    {
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
    }
    attr_md.vloc = BLE_GATTS_VLOC_STACK;

    ble_uuid.type = uuid_type;
    ble_uuid.uuid = uuid;

    memset(&attr_char_value, 0, sizeof(attr_char_value));
    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = init_len;
    attr_char_value.max_len   = max_len;
    attr_char_value.p_value   = (uint8_t *)p_init_value;

    return sd_ble_gatts_characteristic_add(service_handle, &char_md,
                                           &attr_char_value, p_handles);
}

static void on_write(ble_evt_t const *p_ble_evt)
{
    ble_gatts_evt_write_t const *p_w = &p_ble_evt->evt.gatts_evt.params.write;
    if (p_w->handle == m_svc.config_char_handles.value_handle)
    {
        uint16_t len = p_w->len > SECURE_DATA_MAX_LEN ? SECURE_DATA_MAX_LEN : p_w->len;
        memcpy(m_config_buf, p_w->data, len);
        m_config_len = len;
        NRF_LOG_INFO("[SecureData] Config written (%u bytes, over encrypted link)", len);
    }
}

void ble_secure_data_svc_on_ble_evt(ble_evt_t const *p_ble_evt, void *p_context)
{
    (void)p_context;
    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            m_svc.conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            break;
        case BLE_GAP_EVT_DISCONNECTED:
            m_svc.conn_handle = BLE_CONN_HANDLE_INVALID;
            break;
        case BLE_GATTS_EVT_WRITE:
            on_write(p_ble_evt);
            break;
        default:
            break;
    }
}

uint32_t ble_secure_data_svc_init(void)
{
    uint32_t   err_code;
    ble_uuid_t ble_uuid;

    ble_uuid128_t base_uuid = {SECURE_DATA_SVC_UUID_BASE};
    err_code = sd_ble_uuid_vs_add(&base_uuid, &m_svc.uuid_type);
    if (err_code != NRF_SUCCESS) { return err_code; }

    ble_uuid.type = m_svc.uuid_type;
    ble_uuid.uuid = BLE_SECURE_DATA_SVC_UUID;
    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid, &m_svc.service_handle);
    if (err_code != NRF_SUCCESS) { return err_code; }

    /* Secret: read, encryption required. */
    err_code = char_add(BLE_SECURE_SECRET_CHAR_UUID, m_svc.uuid_type,
                        m_svc.service_handle,
                        (const uint8_t *)m_secret_value, sizeof(m_secret_value) - 1,
                        sizeof(m_secret_value) - 1,
                        false, true, &m_svc.secret_char_handles);
    if (err_code != NRF_SUCCESS) { return err_code; }

    /* Config: read + write, encryption required. */
    memset(m_config_buf, 0, sizeof(m_config_buf));
    m_config_len = 0;
    err_code = char_add(BLE_SECURE_CONFIG_CHAR_UUID, m_svc.uuid_type,
                        m_svc.service_handle,
                        m_config_buf, 0, SECURE_DATA_MAX_LEN,
                        true, true, &m_svc.config_char_handles);
    if (err_code != NRF_SUCCESS) { return err_code; }

    /* Info: open read (contrast - readable without pairing). */
    err_code = char_add(BLE_SECURE_INFO_CHAR_UUID, m_svc.uuid_type,
                        m_svc.service_handle,
                        (const uint8_t *)m_info_value, sizeof(m_info_value) - 1,
                        sizeof(m_info_value) - 1,
                        false, false, &m_svc.info_char_handles);
    if (err_code != NRF_SUCCESS) { return err_code; }

    m_svc.conn_handle = BLE_CONN_HANDLE_INVALID;
    NRF_LOG_INFO("[SecureData] Service ready (secret+config encrypted, info open)");
    return NRF_SUCCESS;
}
