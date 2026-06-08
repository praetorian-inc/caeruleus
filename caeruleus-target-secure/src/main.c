/**
 * main.c - Caeruleus-Secure: enforced-encryption + buttonless-DFU BLE target
 *
 * Hardware: nRF52840 DK (PCA10056)
 * SDK:      nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 *
 * Companion to caeruleus-target. Where target 1 enforces nothing, this target:
 *   - bonds via Just Works pairing and marks its Secret/Config characteristics
 *     encryption-required, so they read only over a paired link; and
 *   - exposes an unauthenticated buttonless DFU surface (0xFE59 / 8EC90003).
 *
 * It exercises caeruleus pair / unpair, assess encryption, and assess dfu.
 */

#include <stdint.h>
#include <string.h>

#include "nordic_common.h"
#include "nrf.h"
#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "nrf_sdh_soc.h"
#include "nrf_ble_gatt.h"
#include "nrf_ble_qwr.h"
#include "nrf_pwr_mgmt.h"

#include "app_error.h"
#include "app_timer.h"

#include "ble.h"
#include "ble_err.h"
#include "ble_hci.h"
#include "ble_srv_common.h"
#include "ble_advdata.h"
#include "ble_advertising.h"
#include "ble_conn_params.h"
#include "ble_dis.h"

#include "peer_manager.h"
#include "peer_manager_handler.h"

#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#include "sdk_config.h"
#include "services/secure_data_svc.h"
#include "services/dfu_svc.h"
#include "crash_handler.h"

NRF_BLE_GATT_DEF(m_gatt);
NRF_BLE_QWR_DEF(m_qwr);
BLE_ADVERTISING_DEF(m_advertising);

/* Service BLE observers. */
NRF_SDH_BLE_OBSERVER(m_secure_obs, 2, ble_secure_data_svc_on_ble_evt, NULL);
NRF_SDH_BLE_OBSERVER(m_dfu_obs,    2, ble_dfu_surface_on_ble_evt,     NULL);

static uint8_t m_adv_manuf_data[] = {0x02, 0x00};  /* version 2.0 */

void app_error_fault_handler(uint32_t id, uint32_t pc, uint32_t info)
{
    NRF_LOG_ERROR("Fatal error: id=%u pc=0x%08X info=0x%08X", id, pc, info);
    NRF_LOG_FINAL_FLUSH();
    NVIC_SystemReset();
}

static void ble_stack_init(void)
{
    ret_code_t err_code;
    err_code = nrf_sdh_enable_request();
    APP_ERROR_CHECK(err_code);

    uint32_t ram_start = 0;
    err_code = nrf_sdh_ble_default_cfg_set(1, &ram_start);
    APP_ERROR_CHECK(err_code);

    err_code = nrf_sdh_ble_enable(&ram_start);
    APP_ERROR_CHECK(err_code);
}

static void gap_params_init(void)
{
    ret_code_t              err_code;
    ble_gap_conn_params_t   gap_conn_params;
    ble_gap_conn_sec_mode_t sec_mode;

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&sec_mode);
    err_code = sd_ble_gap_device_name_set(&sec_mode,
                                          (const uint8_t *)DEVICE_NAME,
                                          strlen(DEVICE_NAME));
    APP_ERROR_CHECK(err_code);

    memset(&gap_conn_params, 0, sizeof(gap_conn_params));
    gap_conn_params.min_conn_interval = MIN_CONN_INTERVAL;
    gap_conn_params.max_conn_interval = MAX_CONN_INTERVAL;
    gap_conn_params.slave_latency     = SLAVE_LATENCY;
    gap_conn_params.conn_sup_timeout  = CONN_SUP_TIMEOUT;

    err_code = sd_ble_gap_ppcp_set(&gap_conn_params);
    APP_ERROR_CHECK(err_code);
}

static void gatt_init(void)
{
    ret_code_t err_code = nrf_ble_gatt_init(&m_gatt, NULL);
    APP_ERROR_CHECK(err_code);
}

static void nrf_qwr_error_handler(uint32_t nrf_error)
{
    APP_ERROR_HANDLER(nrf_error);
}

static void services_init(void)
{
    ret_code_t err_code;

    nrf_ble_qwr_init_t qwr_init = {0};
    qwr_init.error_handler = nrf_qwr_error_handler;
    err_code = nrf_ble_qwr_init(&m_qwr, &qwr_init);
    APP_ERROR_CHECK(err_code);

    /* Device Information Service (0x180A) - open, for fingerprinting. */
    ble_dis_init_t dis_init;
    memset(&dis_init, 0, sizeof(dis_init));
    ble_srv_ascii_to_utf8(&dis_init.manufact_name_str, (char *)MANUFACTURER_NAME);
    ble_srv_ascii_to_utf8(&dis_init.fw_rev_str,        (char *)FIRMWARE_REVISION);
    ble_srv_ascii_to_utf8(&dis_init.hw_rev_str,        (char *)HARDWARE_REVISION);
    dis_init.dis_char_rd_sec = SEC_OPEN;
    err_code = ble_dis_init(&dis_init);
    APP_ERROR_CHECK(err_code);

    /* Secure Data Service (0x5EC0) - encryption-required characteristics. */
    err_code = ble_secure_data_svc_init();
    APP_ERROR_CHECK(err_code);

    /* Buttonless DFU surface (0xFE59 / 8EC90003) - unauthenticated entry. */
    err_code = ble_dfu_surface_init();
    APP_ERROR_CHECK(err_code);

    NRF_LOG_INFO("Services: DIS + Secure Data (encrypted) + buttonless DFU");
}

static void on_adv_evt(ble_adv_evt_t ble_adv_evt)
{
    if (ble_adv_evt == BLE_ADV_EVT_IDLE)
    {
        ret_code_t err_code = ble_advertising_start(&m_advertising, BLE_ADV_MODE_FAST);
        APP_ERROR_CHECK(err_code);
    }
}

static void advertising_init(void)
{
    ret_code_t             err_code;
    ble_advertising_init_t init;

    memset(&init, 0, sizeof(init));
    init.advdata.name_type          = BLE_ADVDATA_FULL_NAME;
    init.advdata.include_appearance = false;
    init.advdata.flags              = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;

    ble_advdata_manuf_data_t manuf_data;
    manuf_data.company_identifier = APP_COMPANY_IDENTIFIER;
    manuf_data.data.p_data        = m_adv_manuf_data;
    manuf_data.data.size          = sizeof(m_adv_manuf_data);
    init.advdata.p_manuf_specific_data = &manuf_data;

    static ble_uuid_t adv_uuids[] =
    {
        {BLE_UUID_DEVICE_INFORMATION_SERVICE, BLE_UUID_TYPE_BLE},
        {BLE_DFU_SURFACE_SVC_UUID,                BLE_UUID_TYPE_BLE},
    };
    init.srdata.uuids_complete.uuid_cnt = ARRAY_SIZE(adv_uuids);
    init.srdata.uuids_complete.p_uuids  = adv_uuids;

    init.config.ble_adv_fast_enabled  = true;
    init.config.ble_adv_fast_interval = APP_ADV_INTERVAL;
    init.config.ble_adv_fast_timeout  = APP_ADV_DURATION;
    init.evt_handler                  = on_adv_evt;

    err_code = ble_advertising_init(&m_advertising, &init);
    APP_ERROR_CHECK(err_code);
    ble_advertising_conn_cfg_tag_set(&m_advertising, 1);
}

static void on_conn_params_evt(ble_conn_params_evt_t *p_evt)
{
    if (p_evt->evt_type == BLE_CONN_PARAMS_EVT_FAILED)
    {
        ret_code_t err_code = sd_ble_gap_disconnect(p_evt->conn_handle,
                                                    BLE_HCI_CONN_INTERVAL_UNACCEPTABLE);
        APP_ERROR_CHECK(err_code);
    }
}

static void conn_params_error_handler(uint32_t nrf_error)
{
    APP_ERROR_HANDLER(nrf_error);
}

static void conn_params_init(void)
{
    ret_code_t             err_code;
    ble_conn_params_init_t cp_init;

    memset(&cp_init, 0, sizeof(cp_init));
    cp_init.p_conn_params                  = NULL;
    cp_init.first_conn_params_update_delay = FIRST_CONN_PARAMS_UPDATE_DELAY;
    cp_init.next_conn_params_update_delay  = NEXT_CONN_PARAMS_UPDATE_DELAY;
    cp_init.max_conn_params_update_count   = MAX_CONN_PARAMS_UPDATE_COUNT;
    cp_init.start_on_notify_cccd_handle    = BLE_GATT_HANDLE_INVALID;
    cp_init.disconnect_on_fail             = false;
    cp_init.evt_handler                    = on_conn_params_evt;
    cp_init.error_handler                  = conn_params_error_handler;

    err_code = ble_conn_params_init(&cp_init);
    APP_ERROR_CHECK(err_code);
}

static void pm_evt_handler(pm_evt_t const *p_evt)
{
    pm_handler_on_pm_evt(p_evt);
    pm_handler_disconnect_on_sec_failure(p_evt);
    pm_handler_flash_clean(p_evt);

    switch (p_evt->evt_id)
    {
        case PM_EVT_CONN_SEC_SUCCEEDED:
            NRF_LOG_INFO("Link encrypted (Just Works bond) - protected chars now readable");
            break;
        case PM_EVT_CONN_SEC_FAILED:
            NRF_LOG_WARNING("Pairing/encryption failed");
            break;
        default:
            break;
    }
}

static void peer_manager_init(void)
{
    ret_code_t           err_code;
    ble_gap_sec_params_t sec_param;

    err_code = pm_init();
    APP_ERROR_CHECK(err_code);

    memset(&sec_param, 0, sizeof(sec_param));
    /* Just Works bonding: bond + no MITM + no passkey, so an agent-less central
     * (caeruleus / BlueZ) can complete pairing. Encryption is then required to
     * read the protected characteristics. */
    sec_param.bond           = SEC_PARAM_BOND;
    sec_param.mitm           = SEC_PARAM_MITM;
    sec_param.lesc           = SEC_PARAM_LESC;
    sec_param.keypress       = SEC_PARAM_KEYPRESS;
    sec_param.io_caps        = SEC_PARAM_IO_CAPABILITIES;
    sec_param.oob            = SEC_PARAM_OOB;
    sec_param.min_key_size   = SEC_PARAM_MIN_KEY_SIZE;
    sec_param.max_key_size   = SEC_PARAM_MAX_KEY_SIZE;
    sec_param.kdist_own.enc  = 1;
    sec_param.kdist_own.id   = 1;
    sec_param.kdist_peer.enc = 1;
    sec_param.kdist_peer.id  = 1;

    err_code = pm_sec_params_set(&sec_param);
    APP_ERROR_CHECK(err_code);

    err_code = pm_register(pm_evt_handler);
    APP_ERROR_CHECK(err_code);

    NRF_LOG_INFO("Peer Manager: Just Works bonding (bond=%d mitm=%d lesc=%d)",
                 SEC_PARAM_BOND, SEC_PARAM_MITM, SEC_PARAM_LESC);
}

static void timers_init(void)
{
    /* app_timer is required by ble_conn_params and peer_manager/fds. */
    ret_code_t err_code = app_timer_init();
    APP_ERROR_CHECK(err_code);
}

static void log_init(void)
{
    ret_code_t err_code = NRF_LOG_INIT(NULL);
    APP_ERROR_CHECK(err_code);
    NRF_LOG_DEFAULT_BACKENDS_INIT();
}

static void power_management_init(void)
{
    ret_code_t err_code = nrf_pwr_mgmt_init();
    APP_ERROR_CHECK(err_code);
}

static void idle_state_handle(void)
{
    if (NRF_LOG_PROCESS() == false)
    {
        nrf_pwr_mgmt_run();
    }
}

int main(void)
{
    log_init();
    NRF_LOG_INFO("==============================================");
    NRF_LOG_INFO("  Caeruleus-Secure v%s", FIRMWARE_REVISION);
    NRF_LOG_INFO("  Enforced encryption + buttonless DFU target");
    NRF_LOG_INFO("==============================================");

    crash_handler_init();

    timers_init();
    power_management_init();
    ble_stack_init();
    gap_params_init();
    gatt_init();
    services_init();
    advertising_init();
    conn_params_init();
    peer_manager_init();

    ret_code_t err_code = ble_advertising_start(&m_advertising, BLE_ADV_MODE_FAST);
    APP_ERROR_CHECK(err_code);

    NRF_LOG_INFO("Advertising as \"%s\"", DEVICE_NAME);

    for (;;)
    {
        idle_state_handle();
    }
}
