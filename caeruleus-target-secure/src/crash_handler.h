/**
 * crash_handler.h - Crash handler and watchdog recovery
 *
 * Captures HardFault crash info to retained RAM (.noinit section) so it
 * survives reset.  On next boot, crash_handler_init() detects the magic
 * word, logs the stacked registers, and clears the record.
 *
 * Also provides a 2-second WDT via nrf_drv_wdt.  After a WDT reset the
 * normal startup path in main.c re-enters advertising automatically.
 *
 * SDK: nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#ifndef CRASH_HANDLER_H
#define CRASH_HANDLER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Crash info - retained across resets in .noinit RAM
 * ------------------------------------------------------------------------- */

/**
 * Stacked Cortex-M4 exception frame captured by HardFault_Handler.
 *
 * Layout matches the hardware-pushed frame (low address first):
 *   R0, R1, R2, R3, R12, LR, PC, PSR
 */
typedef struct
{
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r12;
    uint32_t lr;    /**< Link register at fault.                */
    uint32_t pc;    /**< Program counter at fault.              */
    uint32_t psr;   /**< Program status register at fault.      */
} crash_stacked_regs_t;

/**
 * Crash information record stored in retained (.noinit) RAM.
 *
 * The magic field is set to CRASH_INFO_MAGIC (0xDEADBEEF) by the
 * HardFault handler just before triggering a system reset.  On the
 * next boot crash_handler_init() checks for the magic value; if
 * present it logs the record and clears it.
 */
typedef struct
{
    uint32_t             magic;       /**< CRASH_INFO_MAGIC when valid.  */
    crash_stacked_regs_t regs;        /**< Stacked exception frame.      */
    uint32_t             crash_count; /**< Running total of crashes.      */
    uint32_t             timestamp;   /**< app_timer tick at fault time.  */
} crash_info_t;

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/**
 * @brief Initialise the crash handler.
 *
 * Checks retained RAM for a previous crash record (magic == 0xDEADBEEF).
 * If found, logs the crash registers via NRF_LOG, increments the running
 * crash count, and clears the magic word so the record is not re-reported.
 *
 * Call this early in main(), after NRF_LOG is initialised.
 */
void crash_handler_init(void);

/**
 * @brief Return a read-only pointer to the crash info record.
 *
 * Useful for higher-level code that wants to inspect the crash count
 * or expose it over BLE.
 *
 * @return Pointer to the retained crash_info_t (always valid).
 */
crash_info_t const *crash_handler_get_info(void);

/* -------------------------------------------------------------------------
 * Watchdog
 * ------------------------------------------------------------------------- */

/**
 * @brief Initialise and start the watchdog timer.
 *
 * Configures nrf_drv_wdt with a WDT_TIMEOUT_MS (2000 ms) reload value,
 * allocates a single channel, and enables the watchdog.  The WDT interrupt
 * callback logs the timeout event before the automatic reset.
 */
void wdt_init(void);

/**
 * @brief Feed (kick) the watchdog.
 *
 * Must be called from the main loop at an interval shorter than
 * WDT_TIMEOUT_MS to prevent a watchdog reset.
 */
void wdt_feed(void);

#ifdef __cplusplus
}
#endif

#endif /* CRASH_HANDLER_H */
