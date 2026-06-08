/**
 * crash_handler.c - Crash handler and watchdog recovery
 *
 * HardFault_Handler is a naked function that extracts the Cortex-M4
 * exception frame from the correct stack pointer (MSP or PSP), writes
 * it into a retained-RAM struct, and triggers NVIC_SystemReset().
 *
 * On the following boot crash_handler_init() detects the magic sentinel
 * and logs the crash details via NRF_LOG before clearing it.
 *
 * The watchdog uses nrf_drv_wdt with a 2-second timeout.  A WDT reset
 * simply restarts the firmware, which re-enters advertising via the
 * normal main() startup path.
 *
 * SDK: nRF5 SDK 17.1.0 + SoftDevice S140 v7.2.0
 */

#include "crash_handler.h"
#include "sdk_config.h"

#include <string.h>

#include "app_timer.h"
#include "nrf_drv_wdt.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

/* =========================================================================
 * Retained RAM - survives reset (placed in .noinit section)
 * ========================================================================= */

/**
 * Crash info lives in .noinit so the C runtime will NOT zero it during
 * startup.  The linker script must define a .noinit output section that
 * maps to RAM without an initialisation load region.
 */
static crash_info_t m_crash_info __attribute__((section(".noinit")));

/* =========================================================================
 * HardFault_Handler - naked, no prologue/epilogue
 * ========================================================================= */

/**
 * Naked helper called with the faulting stack pointer in R0.
 * Copies the hardware-pushed registers into m_crash_info, sets the
 * magic word, captures the app_timer tick, and resets.
 */
void crash_handler_store_and_reset(uint32_t *p_stack_frame)
{
    m_crash_info.regs.r0  = p_stack_frame[0];
    m_crash_info.regs.r1  = p_stack_frame[1];
    m_crash_info.regs.r2  = p_stack_frame[2];
    m_crash_info.regs.r3  = p_stack_frame[3];
    m_crash_info.regs.r12 = p_stack_frame[4];
    m_crash_info.regs.lr  = p_stack_frame[5];
    m_crash_info.regs.pc  = p_stack_frame[6];
    m_crash_info.regs.psr = p_stack_frame[7];

    /* Preserve the running crash count across resets. */
    if (m_crash_info.magic != CRASH_INFO_MAGIC)
    {
        m_crash_info.crash_count = 0;
    }
    m_crash_info.crash_count++;

    /* Snapshot the app_timer tick counter (may be 0 if timer not started). */
    m_crash_info.timestamp = app_timer_cnt_get();

    /* Arm the magic word so the next boot knows a crash occurred. */
    m_crash_info.magic = CRASH_INFO_MAGIC;

    NVIC_SystemReset();
}

/**
 * Override the default (weak) HardFault_Handler.
 *
 * This is a naked function: the compiler emits no prologue or epilogue,
 * so register state is exactly as the hardware left it.  We test bit 2
 * of EXC_RETURN (in LR) to determine whether the faulting context used
 * MSP or PSP, then branch to the C helper with the correct SP in R0.
 */
void __attribute__((naked)) HardFault_Handler(void)
{
    __asm volatile(
        "tst    lr, #4          \n"  /* Test bit 2 of EXC_RETURN.          */
        "ite    eq              \n"
        "mrseq  r0, msp         \n"  /* EXC_RETURN[2]==0 -> MSP was used.  */
        "mrsne  r0, psp         \n"  /* EXC_RETURN[2]==1 -> PSP was used.  */
        "b      crash_handler_store_and_reset \n"
    );
}

/* =========================================================================
 * crash_handler_init - call early in main()
 * ========================================================================= */

void crash_handler_init(void)
{
    if (m_crash_info.magic == CRASH_INFO_MAGIC)
    {
        NRF_LOG_ERROR("=== CRASH DETECTED (total: %u) ===",
                      m_crash_info.crash_count);
        NRF_LOG_ERROR("  R0  = 0x%08X   R1  = 0x%08X",
                      m_crash_info.regs.r0,
                      m_crash_info.regs.r1);
        NRF_LOG_ERROR("  R2  = 0x%08X   R3  = 0x%08X",
                      m_crash_info.regs.r2,
                      m_crash_info.regs.r3);
        NRF_LOG_ERROR("  R12 = 0x%08X   LR  = 0x%08X",
                      m_crash_info.regs.r12,
                      m_crash_info.regs.lr);
        NRF_LOG_ERROR("  PC  = 0x%08X   PSR = 0x%08X",
                      m_crash_info.regs.pc,
                      m_crash_info.regs.psr);
        NRF_LOG_ERROR("  Tick at fault: %u",
                      m_crash_info.timestamp);

        /* Flush the log backend so the crash report is visible on RTT
         * even if the system resets again quickly. */
        NRF_LOG_FLUSH();

        /* Clear the magic so we don't re-report the same crash. */
        m_crash_info.magic = 0;
    }
    else
    {
        NRF_LOG_INFO("No previous crash detected.");
    }
}

crash_info_t const *crash_handler_get_info(void)
{
    return &m_crash_info;
}

/* =========================================================================
 * Watchdog (nrf_drv_wdt)
 * ========================================================================= */

/** Single WDT channel handle. */
static nrf_drv_wdt_channel_id m_wdt_channel;

/**
 * WDT interrupt callback - fires just before the WDT forces a reset.
 * We have roughly two 32 kHz clock cycles (~60 us) to execute here.
 */
static void wdt_event_handler(void)
{
    NRF_LOG_ERROR("WDT: timeout - system will reset");
    /* NOTE: NRF_LOG_FLUSH() is intentionally omitted here.  The WDT
     * interrupt fires at the highest priority and the reset is
     * imminent; attempting a blocking flush could itself hang.  The
     * crash_handler_init() on the next boot will log the event. */
}

void wdt_init(void)
{
    ret_code_t err_code;

    nrf_drv_wdt_config_t config = NRF_DRV_WDT_DEAFULT_CONFIG;
    config.reload_value = WDT_TIMEOUT_MS;

    err_code = nrf_drv_wdt_init(&config, wdt_event_handler);
    APP_ERROR_CHECK(err_code);

    err_code = nrf_drv_wdt_channel_alloc(&m_wdt_channel);
    APP_ERROR_CHECK(err_code);

    nrf_drv_wdt_enable();

    NRF_LOG_INFO("WDT: enabled with %u ms timeout", WDT_TIMEOUT_MS);
}

void wdt_feed(void)
{
    nrf_drv_wdt_channel_feed(m_wdt_channel);
}
