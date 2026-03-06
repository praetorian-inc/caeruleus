/* Linker script for nRF52840 with SoftDevice S140 v7.2.0
 *
 * Memory layout:
 *   Flash: 0x00027000 - 0x00100000  (SoftDevice occupies 0x00000000-0x00027000)
 *   RAM:   0x20002A98 - 0x20040000  (SoftDevice uses lower RAM)
 *
 * The .noinit section is placed at the end of RAM for crash handler
 * retained data that must survive reset without being zeroed.
 */

SEARCH_DIR(.)
GROUP(-lgcc -lc -lnosys)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00027000, LENGTH = 0x000D9000
    RAM (rwx)   : ORIGIN = 0x20003C00, LENGTH = 0x0003C000
    NOINIT (rwx): ORIGIN = 0x2003FE00, LENGTH = 0x00000200
}

SECTIONS
{
    .noinit (NOLOAD) :
    {
        PROVIDE(__start_noinit = .);
        KEEP(*(.noinit))
        PROVIDE(__stop_noinit = .);
    } > NOINIT
}

SECTIONS
{
    . = ALIGN(4);
    .mem_section_dummy_ram :
    {
    }
    .log_dynamic_data :
    {
        PROVIDE(__start_log_dynamic_data = .);
        KEEP(*(SORT(.log_dynamic_data*)))
        PROVIDE(__stop_log_dynamic_data = .);
    } > RAM
    .log_filter_data :
    {
        PROVIDE(__start_log_filter_data = .);
        KEEP(*(SORT(.log_filter_data*)))
        PROVIDE(__stop_log_filter_data = .);
    } > RAM
    .fs_data :
    {
        PROVIDE(__start_fs_data = .);
        KEEP(*(.fs_data))
        PROVIDE(__stop_fs_data = .);
    } > RAM

} INSERT AFTER .data;

SECTIONS
{
    .mem_section_dummy_rom :
    {
    }
    .sdh_soc_observers :
    {
        PROVIDE(__start_sdh_soc_observers = .);
        KEEP(*(SORT(.sdh_soc_observers*)))
        PROVIDE(__stop_sdh_soc_observers = .);
    } > FLASH
    .sdh_ble_observers :
    {
        PROVIDE(__start_sdh_ble_observers = .);
        KEEP(*(SORT(.sdh_ble_observers*)))
        PROVIDE(__stop_sdh_ble_observers = .);
    } > FLASH
    .sdh_state_observers :
    {
        PROVIDE(__start_sdh_state_observers = .);
        KEEP(*(SORT(.sdh_state_observers*)))
        PROVIDE(__stop_sdh_state_observers = .);
    } > FLASH
    .sdh_stack_observers :
    {
        PROVIDE(__start_sdh_stack_observers = .);
        KEEP(*(SORT(.sdh_stack_observers*)))
        PROVIDE(__stop_sdh_stack_observers = .);
    } > FLASH
    .sdh_req_observers :
    {
        PROVIDE(__start_sdh_req_observers = .);
        KEEP(*(SORT(.sdh_req_observers*)))
        PROVIDE(__stop_sdh_req_observers = .);
    } > FLASH
    .log_const_data :
    {
        PROVIDE(__start_log_const_data = .);
        KEEP(*(SORT(.log_const_data*)))
        PROVIDE(__stop_log_const_data = .);
    } > FLASH
    .nrf_balloc :
    {
        PROVIDE(__start_nrf_balloc = .);
        KEEP(*(.nrf_balloc))
        PROVIDE(__stop_nrf_balloc = .);
    } > FLASH
    .pwr_mgmt_data :
    {
        PROVIDE(__start_pwr_mgmt_data = .);
        KEEP(*(SORT(.pwr_mgmt_data*)))
        PROVIDE(__stop_pwr_mgmt_data = .);
    } > FLASH

} INSERT AFTER .text

INCLUDE "nrf_common.ld"
