/* Minimal BLE advertising test for Makerdiary nRF52840 dongle.
 * No services, no peer manager - just SoftDevice init + advertising.
 */

#include <stdint.h>
#include <string.h>
#include "nordic_common.h"
#include "nrf.h"
#include "app_error.h"
#include "ble.h"
#include "ble_err.h"
#include "ble_hci.h"
#include "ble_srv_common.h"
#include "ble_advdata.h"
#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "nrf_sdh_soc.h"
#include "nrf_pwr_mgmt.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#define APP_BLE_CONN_CFG_TAG    1
#define APP_BLE_OBSERVER_PRIO   3
#define DEVICE_NAME             "Caeruleus-Test"

#define APP_ADV_INTERVAL        MSEC_TO_UNITS(100, UNIT_0_625_MS)

static uint16_t m_conn_handle = BLE_CONN_HANDLE_INVALID;

static void on_ble_evt(ble_evt_t const * p_ble_evt, void * p_context)
{
    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            m_conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            break;
        case BLE_GAP_EVT_DISCONNECTED:
            m_conn_handle = BLE_CONN_HANDLE_INVALID;
            /* Restart advertising */
            {
                ble_gap_adv_params_t adv_params;
                memset(&adv_params, 0, sizeof(adv_params));
                adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
                adv_params.p_peer_addr     = NULL;
                adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
                adv_params.interval        = APP_ADV_INTERVAL;
                adv_params.duration        = 0;

                static uint8_t adv_handle = BLE_GAP_ADV_SET_HANDLE_NOT_SET;
                sd_ble_gap_adv_start(adv_handle, APP_BLE_CONN_CFG_TAG);
            }
            break;
        default:
            break;
    }
}

NRF_SDH_BLE_OBSERVER(m_ble_observer, APP_BLE_OBSERVER_PRIO, on_ble_evt, NULL);

static void ble_stack_init(void)
{
    ret_code_t err_code;

    err_code = nrf_sdh_enable_request();
    APP_ERROR_CHECK(err_code);

    uint32_t ram_start = 0;
    err_code = nrf_sdh_ble_default_cfg_set(APP_BLE_CONN_CFG_TAG, &ram_start);
    APP_ERROR_CHECK(err_code);

    err_code = nrf_sdh_ble_enable(&ram_start);
    APP_ERROR_CHECK(err_code);
}

static void gap_params_init(void)
{
    ret_code_t err_code;
    ble_gap_conn_sec_mode_t sec_mode;

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&sec_mode);

    err_code = sd_ble_gap_device_name_set(&sec_mode,
                                          (const uint8_t *)DEVICE_NAME,
                                          strlen(DEVICE_NAME));
    APP_ERROR_CHECK(err_code);
}

static void advertising_init(void)
{
    ret_code_t err_code;
    ble_advdata_t advdata;
    ble_gap_adv_params_t adv_params;

    memset(&advdata, 0, sizeof(advdata));
    advdata.name_type          = BLE_ADVDATA_FULL_NAME;
    advdata.include_appearance = false;
    advdata.flags              = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;

    static uint8_t  adv_data_encoded[BLE_GAP_ADV_SET_DATA_SIZE_MAX];
    static uint8_t  scan_rsp_encoded[BLE_GAP_ADV_SET_DATA_SIZE_MAX];

    ble_gap_adv_data_t adv_data = {
        .adv_data      = { .p_data = adv_data_encoded, .len = sizeof(adv_data_encoded) },
        .scan_rsp_data = { .p_data = scan_rsp_encoded,  .len = sizeof(scan_rsp_encoded) },
    };

    err_code = ble_advdata_encode(&advdata, adv_data.adv_data.p_data, &adv_data.adv_data.len);
    APP_ERROR_CHECK(err_code);

    adv_data.scan_rsp_data.len = 0;

    memset(&adv_params, 0, sizeof(adv_params));
    adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
    adv_params.p_peer_addr     = NULL;
    adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
    adv_params.interval        = APP_ADV_INTERVAL;
    adv_params.duration        = 0;

    static uint8_t adv_handle = BLE_GAP_ADV_SET_HANDLE_NOT_SET;
    err_code = sd_ble_gap_adv_set_configure(&adv_handle, &adv_data, &adv_params);
    APP_ERROR_CHECK(err_code);

    err_code = sd_ble_gap_adv_start(adv_handle, APP_BLE_CONN_CFG_TAG);
    APP_ERROR_CHECK(err_code);
}

int main(void)
{
    ret_code_t err_code;

    err_code = NRF_LOG_INIT(NULL);
    APP_ERROR_CHECK(err_code);
    NRF_LOG_DEFAULT_BACKENDS_INIT();

    err_code = nrf_pwr_mgmt_init();
    APP_ERROR_CHECK(err_code);

    ble_stack_init();
    gap_params_init();
    advertising_init();

    for (;;)
    {
        NRF_LOG_FLUSH();
        nrf_pwr_mgmt_run();
    }
}
