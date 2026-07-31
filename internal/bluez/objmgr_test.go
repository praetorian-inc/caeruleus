package bluez

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

// handleFromPath is the fallback used on BlueZ < 5.57 (no GattCharacteristic1
// "Handle" D-Bus property). BlueZ names the characteristic object-path segment
// with the DECLARATION handle, but callers want the VALUE handle (what you
// read/write) so the result matches BlueZ >= 5.57 and `enumerate --raw`.
func TestHandleFromPath(t *testing.T) {
	cases := []struct {
		path string
		want uint16
	}{
		// Characteristic: path holds the declaration handle; want value handle (+1).
		{"/org/bluez/hci0/dev_9C_9C_1F_F2_88_86/service0028/char0029", 0x002a},
		{"/org/bluez/hci0/dev_X/service0014/char0015", 0x0016},
		// Descriptor: its own handle, no offset.
		{"/org/bluez/hci0/dev_X/service0028/char0029/desc002b", 0x002b},
		// Service: declaration handle, no offset.
		{"/org/bluez/hci0/dev_X/service0028", 0x0028},
		// Non-GATT / malformed segment -> 0.
		{"/org/bluez/hci0/dev_X/bogus", 0},
		{"/org/bluez/hci0", 0},
	}
	for _, c := range cases {
		if got := handleFromPath(dbus.ObjectPath(c.path)); got != c.want {
			t.Errorf("handleFromPath(%q) = 0x%04x, want 0x%04x", c.path, got, c.want)
		}
	}
}
