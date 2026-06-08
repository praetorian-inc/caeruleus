/**
 * sensor_sim_svc.h - Sensor Simulation Service (UUID 0x5E45)
 *
 * Deliberately vulnerable BLE service for Caeruleus security testing.
 * Simulates temperature, humidity, and battery level sensors with
 * periodic notifications. All characteristics use open permissions
 * with no encryption - MITM can intercept and spoof sensor data.
 *
 * Characteristics:
 *   Temperature (0x0001) - Read + Notify, int16_t  (0.01 C units)
 *   Humidity    (0x0002) - Read + Notify, uint16_t (0.01% units)
 *   Battery     (0x0003) - Read + Notify, uint8_t  (0-100%)
 */

#ifndef SENSOR_SIM_SVC_H__
#define SENSOR_SIM_SVC_H__

#include <stdint.h>
#include <stdbool.h>
#include "ble.h"
#include "ble_srv_common.h"
#include "nrf_sdh_ble.h"

#ifdef __cplusplus
extern "C" {
#endif

/* BLE observer priority for this service. */
#define BLE_SENSOR_SIM_BLE_OBSERVER_PRIO 2

/**
 * Macro to register a Sensor Simulation Service instance as a BLE observer.
 * Automatically forwards BLE events to the service handler.
 */
#define BLE_SENSOR_SIM_DEF(_name)                                               \
    static ble_sensor_sim_svc_t _name;                                          \
    NRF_SDH_BLE_OBSERVER(_name ## _obs,                                         \
                          BLE_SENSOR_SIM_BLE_OBSERVER_PRIO,                     \
                          ble_sensor_sim_svc_on_ble_evt,                        \
                          &_name)

/**
 * 128-bit base UUID for the Sensor Simulation Service.
 * Full UUID: 0000XXXX-5E45-4173-8392-CA0E01AE0000
 * Stored in little-endian byte order per SoftDevice convention.
 * The 16-bit service/characteristic UUID replaces bytes [12..13].
 */
#define BLE_SENSOR_SIM_BASE_UUID    {0x00, 0x00, 0xAE, 0x01, 0x0E, 0xCA, \
                                     0x92, 0x83, 0x73, 0x41, 0x45, 0x5E, \
                                     0x00, 0x00, 0x00, 0x00}

/** Initial simulated temperature: 22.00 C in 0.01 C units. */
#define SENSOR_SIM_TEMP_INITIAL     2200

/** Initial simulated humidity: 45.00% in 0.01% units. */
#define SENSOR_SIM_HUMID_INITIAL    4500

/** Initial simulated battery level: 85%. */
#define SENSOR_SIM_BATT_INITIAL     85

/** Temperature random variation: +/-0.50 C (50 units of 0.01 C). */
#define SENSOR_SIM_TEMP_VARIATION   50

/** Humidity random variation: +/-1.00% (100 units of 0.01%). */
#define SENSOR_SIM_HUMID_VARIATION  100

/** Battery decrements by 1% every 60 notification ticks (60 seconds). */
#define SENSOR_SIM_BATT_TICK_DIV    60

/**
 * Sensor Simulation Service instance structure.
 * Holds GATT handles, connection state, CCCD tracking, and simulated values.
 */
typedef struct
{
    uint16_t                    service_handle;         /**< Service handle from SoftDevice. */
    ble_gatts_char_handles_t    temp_handles;           /**< Temperature characteristic handles. */
    ble_gatts_char_handles_t    humid_handles;          /**< Humidity characteristic handles. */
    ble_gatts_char_handles_t    batt_handles;           /**< Battery characteristic handles. */
    uint16_t                    conn_handle;            /**< Current connection handle (BLE_CONN_HANDLE_INVALID if none). */
    uint8_t                     uuid_type;              /**< UUID type registered with SoftDevice. */

    /* CCCD notification enable flags. */
    bool                        temp_notify_enabled;    /**< True if temperature CCCD is enabled. */
    bool                        humid_notify_enabled;   /**< True if humidity CCCD is enabled. */
    bool                        batt_notify_enabled;    /**< True if battery CCCD is enabled. */

    /* Simulated sensor values. */
    int16_t                     temperature;            /**< Current temperature in 0.01 C. */
    uint16_t                    humidity;               /**< Current humidity in 0.01%. */
    uint8_t                     battery_level;          /**< Current battery 0-100%. */
    uint32_t                    tick_count;             /**< Notification tick counter for battery drain. */
} ble_sensor_sim_svc_t;

/**
 * Initialize the Sensor Simulation Service.
 *
 * Registers the 128-bit vendor-specific base UUID, adds the primary service,
 * and adds all three characteristics (temperature, humidity, battery) with
 * open read permissions and CCCD descriptors for notifications.
 *
 * @param[in,out] p_svc  Pointer to the service instance structure.
 *
 * @retval NRF_SUCCESS              Service initialized successfully.
 * @retval NRF_ERROR_INVALID_PARAM  NULL pointer supplied.
 * @retval Other                    Error codes from sd_ble_uuid_vs_add or
 *                                  sd_ble_gatts_service_add / characteristic_add.
 */
uint32_t ble_sensor_sim_svc_init(ble_sensor_sim_svc_t * p_svc);

/**
 * Handle BLE stack events for the Sensor Simulation Service.
 *
 * Routes connect, disconnect, and GATTS write events to update
 * connection state and CCCD flags. Registered automatically via
 * BLE_SENSOR_SIM_DEF macro.
 *
 * @param[in]     p_ble_evt  Pointer to the BLE event.
 * @param[in,out] p_context  Pointer to the service instance (cast from void*).
 */
void ble_sensor_sim_svc_on_ble_evt(ble_evt_t const * p_ble_evt, void * p_context);

/**
 * Update simulated sensor values and send notifications.
 *
 * Call this from a 1-second app_timer handler. Applies random variation
 * to temperature and humidity, decrements battery periodically, and sends
 * GATT notifications for each characteristic whose CCCD is enabled.
 *
 * @param[in,out] p_svc  Pointer to the service instance structure.
 *
 * @retval NRF_SUCCESS              All enabled notifications sent (or none enabled).
 * @retval NRF_ERROR_INVALID_STATE  Not connected.
 * @retval Other                    Error codes from sd_ble_gatts_hvx.
 */
uint32_t ble_sensor_sim_svc_notify(ble_sensor_sim_svc_t * p_svc);

#ifdef __cplusplus
}
#endif

#endif /* SENSOR_SIM_SVC_H__ */
