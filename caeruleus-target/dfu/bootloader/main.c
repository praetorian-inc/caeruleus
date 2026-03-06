/**
 * main.c -- Caeruleus-Target DFU Bootloader
 *
 * Deliberately vulnerable Nordic Secure DFU bootloader for the
 * nRF52840 DK (PCA10056). Based on the nRF5 SDK 17.1.0
 * secure_bootloader example with ALL security stripped:
 *
 *   - NRF_DFU_REQUIRE_SIGNED_APP_UPDATE = 0  (unsigned firmware accepted)
 *   - NRF_DFU_APP_DOWNGRADE_PREVENTION  = 0  (version rollback allowed)
 *   - NRF_CRYPTO_ENABLED                = 0  (crypto module disabled)
 *   - Public key in dfu_public_key.c is zeroed out
 *
 * This exists solely as a test target for the caeruleus BLE security
 * testing skill. Never deploy this on production hardware.
 *
 * SDK:       nRF5 SDK 17.1.0
 * SoftDevice: S140 v7.2.0
 */

#include <stdint.h>

#include "boards.h"
#include "nrf_mbr.h"
#include "nrf_bootloader.h"
#include "nrf_bootloader_app_start.h"
#include "nrf_bootloader_info.h"
#include "nrf_dfu.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "app_error.h"
#include "app_error_weak.h"
#include "nrf_delay.h"
#include "nrf_gpio.h"

#if NRF_DFU_BLE_BUTTONLESS_SUPPORTS_BONDS
#include "nrf_dfu_ble_svci_bond_cleanup.h"
#include "nrf_svci_async_handler.h"
#include "nrf_svci_async_function.h"
#endif


/**
 * dfu_observer -- Log DFU lifecycle events via RTT.
 *
 * Called by the bootloader/DFU library whenever the DFU state
 * machine transitions. We use this to provide visibility into
 * what the bootloader is doing during a firmware update, which
 * is useful when validating the caeruleus test-dfu flow.
 */
static void dfu_observer(nrf_dfu_evt_type_t evt_type)
{
    switch (evt_type)
    {
        case NRF_DFU_EVT_DFU_INITIALIZED:
            NRF_LOG_INFO("DFU: initialized (unsigned mode, no rollback protection)");
            break;

        case NRF_DFU_EVT_DFU_STARTED:
            NRF_LOG_INFO("DFU: firmware transfer started");
            break;

        case NRF_DFU_EVT_OBJECT_RECEIVED:
            NRF_LOG_INFO("DFU: object received");
            break;

        case NRF_DFU_EVT_DFU_COMPLETED:
            NRF_LOG_INFO("DFU: firmware transfer completed -- resetting");
            break;

        case NRF_DFU_EVT_DFU_FAILED:
            NRF_LOG_WARNING("DFU: firmware transfer failed");
            break;

        case NRF_DFU_EVT_DFU_ABORTED:
            NRF_LOG_WARNING("DFU: firmware transfer aborted");
            break;

        case NRF_DFU_EVT_TRANSPORT_ACTIVATED:
            NRF_LOG_INFO("DFU: BLE transport activated -- awaiting connection");
            break;

        case NRF_DFU_EVT_TRANSPORT_DEACTIVATED:
            NRF_LOG_INFO("DFU: BLE transport deactivated");
            break;

        default:
            NRF_LOG_DEBUG("DFU: event %d", evt_type);
            break;
    }
}


/**
 * app_error_fault_handler -- Override the default error handler.
 *
 * On a fault we log the location and spin so a debugger can attach
 * via SWD. In production this would be a reset; for a test target we
 * want to preserve state for analysis.
 */
void app_error_fault_handler(uint32_t id, uint32_t pc, uint32_t info)
{
    NRF_LOG_ERROR("FATAL: id=0x%08x pc=0x%08x info=0x%08x", id, pc, info);
    NRF_LOG_FINAL_FLUSH();

    /* On debug builds, halt so a debugger can inspect the fault. */
#ifdef DEBUG
    __BKPT(0);
#endif

    /* Spin indefinitely -- reset via watchdog or debugger. */
    for (;;)
    {
        /* Intentionally empty. */
    }
}


/**
 * main -- Bootloader entry point.
 *
 * Execution flow:
 *   1. Initialize logging (RTT backend).
 *   2. Call nrf_bootloader_init() with our observer callback.
 *      - The bootloader checks DFU settings in flash.
 *      - If a valid application exists and no DFU trigger is set,
 *        it jumps directly to the application.
 *      - If a DFU trigger is set (buttonless DFU, pin reset, or
 *        no valid app), it enters DFU mode and activates the BLE
 *        transport, advertising the DFU service (UUID 0xFE59).
 *   3. nrf_bootloader_init() only returns on error.
 */
int main(void)
{
    uint32_t ret_val;

    /* ---- Logging ---- */
    (void) NRF_LOG_INIT(NULL);
    NRF_LOG_DEFAULT_BACKENDS_INIT();

    NRF_LOG_INFO("--------------------------------------------");
    NRF_LOG_INFO("Caeruleus-Target DFU Bootloader");
    NRF_LOG_INFO("SDK 17.1.0 / S140 v7.2.0 / nRF52840");
    NRF_LOG_INFO("WARNING: signature verification DISABLED");
    NRF_LOG_INFO("WARNING: downgrade prevention DISABLED");
    NRF_LOG_INFO("--------------------------------------------");
    NRF_LOG_FLUSH();

    /* ---- Bootloader init ---- */

    /*
     * nrf_bootloader_init() performs the following:
     *   - Initializes the DFU settings page (nrf_dfu_settings_init(true)).
     *   - Validates the installed application image.
     *   - Checks for DFU trigger conditions:
     *       * Buttonless DFU GPREGRET flag
     *       * No valid application present
     *       * Retention register set by application
     *   - If DFU mode: activates BLE transport, enters DFU event loop.
     *   - If app valid and no trigger: boots the application.
     *
     * The `true` parameter to nrf_dfu_settings_init means we write
     * default settings to flash if no valid settings page exists.
     *
     * Because NRF_DFU_REQUIRE_SIGNED_APP_UPDATE=0 in sdk_config.h,
     * the init-packet signature check is skipped entirely. Any
     * well-formed DFU package will be accepted regardless of origin.
     */
    ret_val = nrf_bootloader_init(dfu_observer);
    APP_ERROR_CHECK(ret_val);

    /*
     * Should never reach here. nrf_bootloader_init either boots
     * the application (does not return) or enters the DFU event
     * loop (does not return). If we get here something went wrong.
     */
    NRF_LOG_ERROR("Bootloader init returned unexpectedly: 0x%08x", ret_val);
    NRF_LOG_FINAL_FLUSH();

    /* Reset as a last resort. */
    NVIC_SystemReset();
}
