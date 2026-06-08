/**
 * dfu_svc.c - Buttonless DFU surface (0xFE59 / 8EC90003) implementation
 *
 * SDK: nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#include "dfu_svc.h"

#include <string.h>
#include "nrf.h"
#include "nrf_soc.h"
#include "ble_gatts.h"
#include "nrf_log.h"

/* GPREGRET value the Secure DFU bootloader checks on boot to stay in DFU mode.
 * Defined as BOOTLOADER_DFU_START in nrf_bootloader_info.h; redefined here so
 * this surface does not pull in the bootloader headers. */
#define DFU_GPREGRET_DFU_START 0xB1

static ble_dfu_surface_t m_dfu;

static uint32_t buttonless_char_add(void)
{
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_md_t cccd_md;
    ble_gatts_attr_t    attr_char_value;
    ble_uuid_t          ble_uuid;
    ble_gatts_attr_md_t attr_md;

    /* The real Nordic buttonless characteristic is write + indicate. The
     * indicate path needs a CCCD; the SoftDevice adds one when indicate is set. */
    memset(&cccd_md, 0, sizeof(cccd_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);
    cccd_md.vloc = BLE_GATTS_VLOC_STACK;

    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.write    = 1;  /* what assess dfu keys on */
    char_md.char_props.indicate = 1;
    char_md.p_cccd_md           = &cccd_md;

    memset(&attr_md, 0, sizeof(attr_md));
    /* OPEN: unauthenticated buttonless entry (deliberate finding). */
    BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
    attr_md.vloc = BLE_GATTS_VLOC_STACK;

    ble_uuid.type = m_dfu.uuid_type;
    ble_uuid.uuid = BLE_DFU_BUTTONLESS_CHAR_UUID;

    memset(&attr_char_value, 0, sizeof(attr_char_value));
    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = 0;
    attr_char_value.max_len   = 16;

    return sd_ble_gatts_characteristic_add(m_dfu.service_handle, &char_md,
                                           &attr_char_value,
                                           &m_dfu.buttonless_char_handles);
}

static void enter_dfu(void)
{
    NRF_LOG_INFO("[DFU] Buttonless entry requested - setting GPREGRET and resetting");
    NRF_LOG_FINAL_FLUSH();
    (void)sd_power_gpregret_clr(0, 0xFFFFFFFF);
    (void)sd_power_gpregret_set(0, DFU_GPREGRET_DFU_START);
    NVIC_SystemReset();
}

void ble_dfu_surface_on_ble_evt(ble_evt_t const *p_ble_evt, void *p_context)
{
    (void)p_context;
    if (p_ble_evt->header.evt_id != BLE_GATTS_EVT_WRITE)
    {
        return;
    }
    ble_gatts_evt_write_t const *p_w = &p_ble_evt->evt.gatts_evt.params.write;
    if (p_w->handle == m_dfu.buttonless_char_handles.value_handle && p_w->len >= 1)
    {
        /* Any opcode triggers entry; the real bootloader validates the image. */
        enter_dfu();
    }
}

uint32_t ble_dfu_surface_init(void)
{
    uint32_t   err_code;
    ble_uuid_t ble_uuid;

    /* Register the Nordic buttonless base UUID for the characteristic. */
    ble_uuid128_t base_uuid = {DFU_BUTTONLESS_UUID_BASE};
    err_code = sd_ble_uuid_vs_add(&base_uuid, &m_dfu.uuid_type);
    if (err_code != NRF_SUCCESS) { return err_code; }

    /* Service uses the SIG-assigned 16-bit UUID 0xFE59. */
    ble_uuid.type = BLE_UUID_TYPE_BLE;
    ble_uuid.uuid = BLE_DFU_SURFACE_SVC_UUID;
    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid, &m_dfu.service_handle);
    if (err_code != NRF_SUCCESS) { return err_code; }

    err_code = buttonless_char_add();
    if (err_code != NRF_SUCCESS) { return err_code; }

    NRF_LOG_INFO("[DFU] Buttonless DFU surface ready (0xFE59 / 8EC90003, OPEN write)");
    return NRF_SUCCESS;
}
