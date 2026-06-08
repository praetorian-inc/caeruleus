package cli

import "testing"

func TestShortUUID(t *testing.T) {
	cases := map[string]string{
		// adopted (SIG base) -> compact 16-bit form
		"00002a00-0000-1000-8000-00805f9b34fb": "0x2A00",
		"0000fe59-0000-1000-8000-00805f9b34fb": "0xFE59",
		"00002902-0000-1000-8000-00805f9b34fb": "0x2902",
		// custom / vendor -> unchanged
		"00ca0001-bede-ad43-4145-52554c455500": "00ca0001-bede-ad43-4145-52554c455500",
		"78900001-abcd-ef01-2233-44556677aabb": "78900001-abcd-ef01-2233-44556677aabb",
	}
	for in, want := range cases {
		if got := shortUUID(in); got != want {
			t.Errorf("shortUUID(%q) = %q, want %q", in, got, want)
		}
	}
}
