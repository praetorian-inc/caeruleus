package cli

import (
	"fmt"
	"strings"
)

// GAP Appearance values from the Bluetooth SIG Assigned Numbers.
// The uint16 is (category << 6) | subcategory as it appears on the wire
// and in BlueZ's Appearance D-Bus property.
var appearanceTable = map[uint16]string{
	0x0040: "Phone",
	0x0080: "Computer",
	0x0081: "Desktop",
	0x0082: "Server",
	0x00C0: "Watch",
	0x00C1: "Sports Watch",
	0x00C2: "Smartwatch",
	0x0100: "Clock",
	0x0140: "Display",
	0x0180: "Remote Control",
	0x01C0: "Eye-glasses",
	0x0200: "Tag",
	0x0240: "Keyring",
	0x0280: "Media Player",
	0x02C0: "Barcode Scanner",
	0x0300: "Thermometer",
	0x0301: "Ear Thermometer",
	0x0340: "Heart Rate Sensor",
	0x0341: "HR Belt",
	0x0380: "Blood Pressure",
	0x0381: "BP Arm",
	0x0382: "BP Wrist",
	0x03C0: "HID",
	0x03C1: "Keyboard",
	0x03C2: "Mouse",
	0x03C3: "Joystick",
	0x03C4: "Gamepad",
	0x03C5: "Digitizer",
	0x03C6: "Card Reader",
	0x03C7: "Digital Pen",
	0x03C8: "Barcode Scanner",
	0x03C9: "Touchpad",
	0x03CA: "Presentation Remote",
	0x0400: "Glucose Meter",
	0x0440: "Running Sensor",
	0x0480: "Cycling",
	0x0481: "Cycling Computer",
	0x0482: "Speed Sensor",
	0x0483: "Cadence Sensor",
	0x0484: "Power Sensor",
	0x0485: "Speed+Cadence",
	0x04C0: "Control Device",
	0x0500: "Network Device",
	0x0540: "Sensor",
	0x0541: "Motion Sensor",
	0x0542: "Air Quality",
	0x0543: "Temp Sensor",
	0x0544: "Humidity Sensor",
	0x0545: "Leak Sensor",
	0x0546: "Smoke Sensor",
	0x0547: "Occupancy Sensor",
	0x0548: "Contact Sensor",
	0x0580: "Light Fixture",
	0x05C0: "Fan",
	0x0600: "HVAC",
	0x0640: "Air Conditioning",
	0x0680: "Humidifier",
	0x06C0: "Heating",
	0x0700: "Access Control",
	0x0740: "Motorized Device",
	0x0780: "Power Device",
	0x07C0: "Light Source",
	0x0800: "Window Covering",
	0x0840: "Audio Sink",
	0x0880: "Audio Source",
	0x08C0: "Vehicle",
	0x0900: "Appliance",
	0x0940: "Wearable Audio",
	0x0A40: "Hearing Aid",
	0x0A80: "Gaming",
	0x0C40: "Pulse Oximeter",
	0x0C80: "Weight Scale",
	0x0CC0: "Mobility Device",
	0x0D00: "CGM",
	0x0D40: "Insulin Pump",
	0x0D80: "Medication Delivery",
	0x0DC0: "Spirometer",
	0x1440: "Outdoor Sports",
	0x1441: "Location Display",
	0x1442: "Location+Nav Display",
	0x1443: "Location Pod",
	0x1444: "Location+Nav Pod",
}

// Adopted GATT service UUIDs (16-bit) that imply a device category.
// Infrastructure services (GAP, GATT, DIS, Battery, etc.) are excluded
// via infraServices below.
var serviceTypeTable = map[uint16]string{
	0x1802: "Alert",
	0x1803: "Alert",
	0x1805: "Clock",
	0x1808: "Glucose Meter",
	0x1809: "Thermometer",
	0x180D: "Heart Rate",
	0x180E: "Phone",
	0x1810: "Blood Pressure",
	0x1812: "HID",
	0x1814: "Running Sensor",
	0x1816: "Cycling",
	0x1818: "Cycling Power",
	0x1819: "Location+Nav",
	0x181A: "Env Sensor",
	0x181B: "Body Comp",
	0x181D: "Weight Scale",
	0x181F: "CGM",
	0x1822: "Pulse Oximeter",
	0x1826: "Fitness Machine",
	0x183A: "Insulin Pump",
	0xFE59: "Nordic DFU",
	0xFEAA: "Eddystone Beacon",
}

// infraServices are adopted services that don't identify the device type.
var infraServices = map[uint16]bool{
	0x1800: true, // Generic Access
	0x1801: true, // Generic Attribute
	0x180A: true, // Device Information
	0x180F: true, // Battery
	0x1813: true, // Scan Parameters
	0x181E: true, // Bond Management
	0x1824: true, // Transport Discovery
	0x1827: true, // Mesh Provisioning
	0x1828: true, // Mesh Proxy
	0x1829: true, // Reconnection Config
}

// lookupAppearance resolves a GAP Appearance uint16 to a label.
// Tries exact match first (specific subcategory like Keyboard), then
// falls back to the generic category (zeroing the subcategory bits).
func lookupAppearance(appearance uint16) string {
	if label, ok := appearanceTable[appearance]; ok {
		return label
	}
	generic := appearance &^ 0x003F
	if label, ok := appearanceTable[generic]; ok {
		return label
	}
	return ""
}

// inferDeviceType returns a human-readable device type label from the
// GAP Appearance value and advertised service UUIDs. Appearance takes
// priority (it's the device's self-declared type); service UUIDs are a
// fallback. Returns "" when no type can be inferred.
func inferDeviceType(appearance uint16, uuids []string) string {
	if appearance != 0 {
		if label := lookupAppearance(appearance); label != "" {
			return label
		}
		return fmt.Sprintf("Appearance(0x%04x)", appearance)
	}

	for _, u := range uuids {
		u16, ok := extractSIG16(u)
		if !ok || infraServices[u16] {
			continue
		}
		if label, ok := serviceTypeTable[u16]; ok {
			return label
		}
	}
	return ""
}

// extractSIG16 extracts the 16-bit UUID from a SIG base 128-bit UUID.
func extractSIG16(u string) (uint16, bool) {
	u = strings.ToLower(u)
	if !strings.HasSuffix(u, "-0000-1000-8000-00805f9b34fb") || len(u) < 8 {
		return 0, false
	}
	if !strings.HasPrefix(u, "0000") {
		return 0, false
	}
	var v uint16
	_, err := fmt.Sscanf(u[4:8], "%x", &v)
	return v, err == nil
}
