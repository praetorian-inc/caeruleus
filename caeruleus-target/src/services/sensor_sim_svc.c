/**
 * sensor_sim_svc.c - Sensor Simulation Service implementation
 *
 * Deliberately vulnerable BLE service for Caeruleus security testing.
 * All characteristics use open permissions with no encryption requirement.
 *
 * VULNERABILITY: Notifications are sent in the clear. An attacker with
 * a sniffer (Ubertooth, nRF Sniffer) can intercept all sensor data.
 * An active MITM relay can also spoof/modify values in transit.
 */

#include "sensor_sim_svc.h"
#include "sdk_config.h"

#include <string.h>
#include <stdlib.h>

#include "ble_srv_common.h"
#include "app_error.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

/* ========================================================================== *
 *  Forward declarations
 * ========================================================================== */

static uint32_t sensor_char_add(ble_sensor_sim_svc_t * p_svc,
                                uint16_t               char_uuid,
                                uint8_t              * p_init_value,
                                uint16_t               init_len,
                                uint16_t               max_len,
                                ble_gatts_char_handles_t * p_handles);

static void on_connect(ble_sensor_sim_svc_t * p_svc, ble_evt_t const * p_ble_evt);
static void on_disconnect(ble_sensor_sim_svc_t * p_svc, ble_evt_t const * p_ble_evt);
static void on_write(ble_sensor_sim_svc_t * p_svc, ble_evt_t const * p_ble_evt);

/* ========================================================================== *
 *  Public API
 * ========================================================================== */

uint32_t ble_sensor_sim_svc_init(ble_sensor_sim_svc_t * p_svc)
{
    uint32_t   err_code;
    ble_uuid_t ble_uuid;

    if (p_svc == NULL)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    /* ---- Zero-initialise instance ---- */
    p_svc->conn_handle        = BLE_CONN_HANDLE_INVALID;
    p_svc->temp_notify_enabled  = false;
    p_svc->humid_notify_enabled = false;
    p_svc->batt_notify_enabled  = false;
    p_svc->temperature        = SENSOR_SIM_TEMP_INITIAL;
    p_svc->humidity           = SENSOR_SIM_HUMID_INITIAL;
    p_svc->battery_level      = SENSOR_SIM_BATT_INITIAL;
    p_svc->tick_count         = 0;

    /* ---- Register vendor-specific 128-bit base UUID ---- */
    ble_uuid128_t base_uuid = {BLE_SENSOR_SIM_BASE_UUID};

    err_code = sd_ble_uuid_vs_add(&base_uuid, &p_svc->uuid_type);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("sensor_sim: sd_ble_uuid_vs_add failed (0x%08X)", err_code);
        return err_code;
    }

    /* ---- Add primary service ---- */
    ble_uuid.type = p_svc->uuid_type;
    ble_uuid.uuid = BLE_SENSOR_SIM_SVC_UUID;

    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid,
                                        &p_svc->service_handle);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("sensor_sim: service_add failed (0x%08X)", err_code);
        return err_code;
    }

    NRF_LOG_INFO("sensor_sim: service registered (handle 0x%04X, uuid_type %d)",
                 p_svc->service_handle, p_svc->uuid_type);

    /* ---- Add Temperature characteristic (int16_t, 2 bytes) ---- */
    int16_t temp_init = (int16_t)p_svc->temperature;
    err_code = sensor_char_add(p_svc,
                               BLE_SENSOR_TEMP_CHAR_UUID,
                               (uint8_t *)&temp_init,
                               sizeof(temp_init),
                               sizeof(temp_init),
                               &p_svc->temp_handles);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("sensor_sim: temp char_add failed (0x%08X)", err_code);
        return err_code;
    }

    /* ---- Add Humidity characteristic (uint16_t, 2 bytes) ---- */
    uint16_t humid_init = p_svc->humidity;
    err_code = sensor_char_add(p_svc,
                               BLE_SENSOR_HUMID_CHAR_UUID,
                               (uint8_t *)&humid_init,
                               sizeof(humid_init),
                               sizeof(humid_init),
                               &p_svc->humid_handles);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("sensor_sim: humid char_add failed (0x%08X)", err_code);
        return err_code;
    }

    /* ---- Add Battery characteristic (uint8_t, 1 byte) ---- */
    uint8_t batt_init = p_svc->battery_level;
    err_code = sensor_char_add(p_svc,
                               BLE_SENSOR_BATT_CHAR_UUID,
                               &batt_init,
                               sizeof(batt_init),
                               sizeof(batt_init),
                               &p_svc->batt_handles);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("sensor_sim: batt char_add failed (0x%08X)", err_code);
        return err_code;
    }

    NRF_LOG_INFO("sensor_sim: all characteristics added");
    return NRF_SUCCESS;
}

void ble_sensor_sim_svc_on_ble_evt(ble_evt_t const * p_ble_evt, void * p_context)
{
    ble_sensor_sim_svc_t * p_svc = (ble_sensor_sim_svc_t *)p_context;

    if (p_svc == NULL || p_ble_evt == NULL)
    {
        return;
    }

    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            on_connect(p_svc, p_ble_evt);
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            on_disconnect(p_svc, p_ble_evt);
            break;

        case BLE_GATTS_EVT_WRITE:
            on_write(p_svc, p_ble_evt);
            break;

        default:
            break;
    }
}

uint32_t ble_sensor_sim_svc_notify(ble_sensor_sim_svc_t * p_svc)
{
    uint32_t err_code;

    if (p_svc == NULL)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    if (p_svc->conn_handle == BLE_CONN_HANDLE_INVALID)
    {
        return NRF_ERROR_INVALID_STATE;
    }

    p_svc->tick_count++;

    /* ---- Update simulated temperature ---- */
    {
        int16_t variation = (int16_t)((rand() % (2 * SENSOR_SIM_TEMP_VARIATION + 1))
                                       - SENSOR_SIM_TEMP_VARIATION);
        p_svc->temperature = (int16_t)(SENSOR_SIM_TEMP_INITIAL + variation);
    }

    /* ---- Update simulated humidity ---- */
    {
        int16_t variation = (int16_t)((rand() % (2 * SENSOR_SIM_HUMID_VARIATION + 1))
                                       - SENSOR_SIM_HUMID_VARIATION);
        int32_t new_humid = (int32_t)SENSOR_SIM_HUMID_INITIAL + variation;
        if (new_humid < 0)    new_humid = 0;
        if (new_humid > 10000) new_humid = 10000;
        p_svc->humidity = (uint16_t)new_humid;
    }

    /* ---- Update simulated battery ---- */
    if ((p_svc->tick_count % SENSOR_SIM_BATT_TICK_DIV) == 0)
    {
        if (p_svc->battery_level > 0)
        {
            p_svc->battery_level--;
            NRF_LOG_INFO("sensor_sim: battery now %d%%", p_svc->battery_level);
        }
    }

    /* ---- Send temperature notification ---- */
    if (p_svc->temp_notify_enabled)
    {
        uint16_t len = sizeof(p_svc->temperature);
        ble_gatts_hvx_params_t hvx_params;
        memset(&hvx_params, 0, sizeof(hvx_params));
        hvx_params.handle = p_svc->temp_handles.value_handle;
        hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;
        hvx_params.offset = 0;
        hvx_params.p_len  = &len;
        hvx_params.p_data = (uint8_t *)&p_svc->temperature;

        err_code = sd_ble_gatts_hvx(p_svc->conn_handle, &hvx_params);
        if (err_code != NRF_SUCCESS && err_code != NRF_ERROR_RESOURCES)
        {
            NRF_LOG_WARNING("sensor_sim: temp hvx failed (0x%08X)", err_code);
        }
    }

    /* ---- Send humidity notification ---- */
    if (p_svc->humid_notify_enabled)
    {
        uint16_t len = sizeof(p_svc->humidity);
        ble_gatts_hvx_params_t hvx_params;
        memset(&hvx_params, 0, sizeof(hvx_params));
        hvx_params.handle = p_svc->humid_handles.value_handle;
        hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;
        hvx_params.offset = 0;
        hvx_params.p_len  = &len;
        hvx_params.p_data = (uint8_t *)&p_svc->humidity;

        err_code = sd_ble_gatts_hvx(p_svc->conn_handle, &hvx_params);
        if (err_code != NRF_SUCCESS && err_code != NRF_ERROR_RESOURCES)
        {
            NRF_LOG_WARNING("sensor_sim: humid hvx failed (0x%08X)", err_code);
        }
    }

    /* ---- Send battery notification ---- */
    if (p_svc->batt_notify_enabled)
    {
        uint16_t len = sizeof(p_svc->battery_level);
        ble_gatts_hvx_params_t hvx_params;
        memset(&hvx_params, 0, sizeof(hvx_params));
        hvx_params.handle = p_svc->batt_handles.value_handle;
        hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;
        hvx_params.offset = 0;
        hvx_params.p_len  = &len;
        hvx_params.p_data = &p_svc->battery_level;

        err_code = sd_ble_gatts_hvx(p_svc->conn_handle, &hvx_params);
        if (err_code != NRF_SUCCESS && err_code != NRF_ERROR_RESOURCES)
        {
            NRF_LOG_WARNING("sensor_sim: batt hvx failed (0x%08X)", err_code);
        }
    }

    NRF_LOG_DEBUG("sensor_sim: notify tick=%lu temp=%d humid=%u batt=%u",
                  p_svc->tick_count, p_svc->temperature,
                  p_svc->humidity, p_svc->battery_level);

    return NRF_SUCCESS;
}

/* ========================================================================== *
 *  Static helpers
 * ========================================================================== */

/**
 * Add a single sensor characteristic with Read + Notify and open permissions.
 */
static uint32_t sensor_char_add(ble_sensor_sim_svc_t     * p_svc,
                                uint16_t                   char_uuid,
                                uint8_t                  * p_init_value,
                                uint16_t                   init_len,
                                uint16_t                   max_len,
                                ble_gatts_char_handles_t * p_handles)
{
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_md_t cccd_md;
    ble_gatts_attr_t    attr_char_value;
    ble_uuid_t          ble_uuid;
    ble_gatts_attr_md_t attr_md;

    /* ---- CCCD metadata (open read/write so any peer can subscribe) ---- */
    memset(&cccd_md, 0, sizeof(cccd_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);
    cccd_md.vloc = BLE_GATTS_VLOC_STACK;

    /* ---- Characteristic metadata ---- */
    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.read   = 1;
    char_md.char_props.notify = 1;
    char_md.p_char_user_desc  = NULL;
    char_md.p_char_pf         = NULL;
    char_md.p_user_desc_md    = NULL;
    char_md.p_cccd_md         = &cccd_md;
    char_md.p_sccd_md         = NULL;

    /* ---- Attribute metadata (open read, no write to value) ---- */
    memset(&attr_md, 0, sizeof(attr_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
    attr_md.vloc    = BLE_GATTS_VLOC_STACK;
    attr_md.rd_auth = 0;
    attr_md.wr_auth = 0;
    attr_md.vlen    = 0;

    /* ---- UUID ---- */
    ble_uuid.type = p_svc->uuid_type;
    ble_uuid.uuid = char_uuid;

    /* ---- Attribute value ---- */
    memset(&attr_char_value, 0, sizeof(attr_char_value));
    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = init_len;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = max_len;
    attr_char_value.p_value   = p_init_value;

    return sd_ble_gatts_characteristic_add(p_svc->service_handle,
                                           &char_md,
                                           &attr_char_value,
                                           p_handles);
}

/**
 * Handle BLE_GAP_EVT_CONNECTED - store connection handle.
 */
static void on_connect(ble_sensor_sim_svc_t * p_svc, ble_evt_t const * p_ble_evt)
{
    p_svc->conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
    NRF_LOG_INFO("sensor_sim: connected (handle 0x%04X)", p_svc->conn_handle);
}

/**
 * Handle BLE_GAP_EVT_DISCONNECTED - clear connection handle and CCCD state.
 */
static void on_disconnect(ble_sensor_sim_svc_t * p_svc, ble_evt_t const * p_ble_evt)
{
    UNUSED_PARAMETER(p_ble_evt);

    NRF_LOG_INFO("sensor_sim: disconnected (handle 0x%04X)", p_svc->conn_handle);

    p_svc->conn_handle          = BLE_CONN_HANDLE_INVALID;
    p_svc->temp_notify_enabled  = false;
    p_svc->humid_notify_enabled = false;
    p_svc->batt_notify_enabled  = false;
}

/**
 * Handle BLE_GATTS_EVT_WRITE - detect CCCD writes and update notification flags.
 *
 * VULNERABILITY: No authentication check - any connected peer can enable
 * notifications without pairing or encryption.
 */
static void on_write(ble_sensor_sim_svc_t * p_svc, ble_evt_t const * p_ble_evt)
{
    ble_gatts_evt_write_t const * p_evt_write = &p_ble_evt->evt.gatts_evt.params.write;

    /* CCCD writes are always 2 bytes. */
    if (p_evt_write->len != 2)
    {
        return;
    }

    uint16_t cccd_value = uint16_decode(p_evt_write->data);

    /* ---- Temperature CCCD ---- */
    if (p_evt_write->handle == p_svc->temp_handles.cccd_handle)
    {
        p_svc->temp_notify_enabled = ble_srv_is_notification_enabled(p_evt_write->data);
        NRF_LOG_INFO("sensor_sim: temp CCCD %s (0x%04X)",
                     p_svc->temp_notify_enabled ? "enabled" : "disabled", cccd_value);
    }

    /* ---- Humidity CCCD ---- */
    else if (p_evt_write->handle == p_svc->humid_handles.cccd_handle)
    {
        p_svc->humid_notify_enabled = ble_srv_is_notification_enabled(p_evt_write->data);
        NRF_LOG_INFO("sensor_sim: humid CCCD %s (0x%04X)",
                     p_svc->humid_notify_enabled ? "enabled" : "disabled", cccd_value);
    }

    /* ---- Battery CCCD ---- */
    else if (p_evt_write->handle == p_svc->batt_handles.cccd_handle)
    {
        p_svc->batt_notify_enabled = ble_srv_is_notification_enabled(p_evt_write->data);
        NRF_LOG_INFO("sensor_sim: batt CCCD %s (0x%04X)",
                     p_svc->batt_notify_enabled ? "enabled" : "disabled", cccd_value);
    }
}
