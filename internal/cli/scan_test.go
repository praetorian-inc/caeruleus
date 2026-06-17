package cli

import (
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/praetorian-inc/caeruleus/internal/bluez"
)

func TestIndexerObserve(t *testing.T) {
	ix := newIndexer()
	a := dbus.ObjectPath("/org/bluez/hci0/dev_AA")
	b := dbus.ObjectPath("/org/bluez/hci0/dev_BB")

	if idx, first := ix.Observe(a); idx != 1 || !first {
		t.Fatalf("first observe of a = (%d,%v), want (1,true)", idx, first)
	}
	if idx, first := ix.Observe(b); idx != 2 || !first {
		t.Fatalf("first observe of b = (%d,%v), want (2,true)", idx, first)
	}
	// A repeat keeps the original index and is not first-seen.
	if idx, first := ix.Observe(a); idx != 1 || first {
		t.Fatalf("repeat observe of a = (%d,%v), want (1,false)", idx, first)
	}
	if idx, first := ix.Observe(b); idx != 2 || first {
		t.Fatalf("repeat observe of b = (%d,%v), want (2,false)", idx, first)
	}
	if len(ix.order) != 2 {
		t.Fatalf("order len = %d, want 2 (repeats must not append)", len(ix.order))
	}
}

func TestClassify(t *testing.T) {
	base := bluez.DeviceInfo{RSSI: -50, Name: "x", AddrType: "public"}
	cases := []struct {
		name string
		next bluez.DeviceInfo
		want string
	}{
		{"identical re-observation", base, ""},
		{"rssi change", bluez.DeviceInfo{RSSI: -40, Name: "x", AddrType: "public"}, "update"},
		{"name change", bluez.DeviceInfo{RSSI: -50, Name: "y", AddrType: "public"}, "update"},
		{"addr type change", bluez.DeviceInfo{RSSI: -50, Name: "x", AddrType: "random"}, "update"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(base, tc.next); got != tc.want {
				t.Errorf("classify = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeTerminal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text untouched", "Pixel Buds", "Pixel Buds"},
		{"strips ESC so CSI can't start", "ab\x1b[2Jcd", "ab[2Jcd"},
		{"strips ESC and BEL of an OSC title", "x\x1b]0;pwn\x07y", "x]0;pwny"},
		{"strips NUL/BEL/DEL", "a\x00\x07\x7fb", "ab"},
		{"keeps UTF-8 glyphs", "café", "café"},
		{"empty stays empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeTerminal(tc.in); got != tc.want {
				t.Errorf("sanitizeTerminal(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDisplayName(t *testing.T) {
	if got := displayName(bluez.DeviceInfo{Name: "N", Alias: "A"}); got != "N" {
		t.Errorf("Name preferred over Alias: got %q, want %q", got, "N")
	}
	if got := displayName(bluez.DeviceInfo{Alias: "A"}); got != "A" {
		t.Errorf("Alias fallback when Name empty: got %q, want %q", got, "A")
	}
	if got := displayName(bluez.DeviceInfo{Name: "ev\x1bil"}); got != "evil" {
		t.Errorf("name scrubbed for terminal: got %q, want %q", got, "evil")
	}
	// deviceName is the raw (un-scrubbed) selection used by the JSON path.
	if got := deviceName(bluez.DeviceInfo{Name: "ev\x1bil"}); got != "ev\x1bil" {
		t.Errorf("deviceName must stay raw: got %q", got)
	}
}

func TestRssiStr(t *testing.T) {
	if got := rssiStr(0); got != "" {
		t.Errorf("rssiStr(0) = %q, want empty", got)
	}
	if got := rssiStr(-67); got != "-67" {
		t.Errorf("rssiStr(-67) = %q, want -67", got)
	}
}
