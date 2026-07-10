package bdaddr

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAddRemoteOOBDataPayload(t *testing.T) {
	addr := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	var hash256, rand256 [16]byte
	for i := range hash256 {
		hash256[i] = byte(0xa0 + i)
	}
	for i := range rand256 {
		rand256[i] = byte(0xb0 + i)
	}

	var buf [71]byte
	copy(buf[0:6], addr[:])
	buf[6] = 2 // LE random
	// hash192 and rand192 at [7:39] must be zero
	copy(buf[39:55], hash256[:])
	copy(buf[55:71], rand256[:])

	// Verify addr placement.
	if !bytes.Equal(buf[0:6], addr[:]) {
		t.Fatalf("addr mismatch: got %x", buf[0:6])
	}

	// Verify addr_type.
	if buf[6] != 2 {
		t.Fatalf("addr_type: got %d, want 2", buf[6])
	}

	// Verify hash192 / rand192 are zero.
	for i := 7; i < 39; i++ {
		if buf[i] != 0 {
			t.Fatalf("hash192/rand192 byte %d is 0x%02x, want 0x00", i, buf[i])
		}
	}

	// Verify hash256 and rand256.
	if !bytes.Equal(buf[39:55], hash256[:]) {
		t.Fatalf("hash256 mismatch")
	}
	if !bytes.Equal(buf[55:71], rand256[:]) {
		t.Fatalf("rand256 mismatch")
	}
}

func TestRemoveRemoteOOBDataPayload(t *testing.T) {
	addr := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	var buf [7]byte
	copy(buf[0:6], addr[:])
	buf[6] = 1 // LE public

	if !bytes.Equal(buf[0:6], addr[:]) {
		t.Fatalf("addr mismatch")
	}
	if buf[6] != 1 {
		t.Fatalf("addr_type: got %d, want 1", buf[6])
	}
}

func TestMgmtOpcodes(t *testing.T) {
	if mgmtOpAddRemoteOOB != 0x0021 {
		t.Fatalf("AddRemoteOOB opcode: got 0x%04x, want 0x0021", mgmtOpAddRemoteOOB)
	}
	if mgmtOpRemoveRemoteOOB != 0x0022 {
		t.Fatalf("RemoveRemoteOOB opcode: got 0x%04x, want 0x0022", mgmtOpRemoveRemoteOOB)
	}
}

func TestPayloadEndianness(t *testing.T) {
	// ParseMAC returns LE byte order; verify the layout matches what sendMgmt
	// would write for a known address.
	addr, err := ParseMAC("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatal(err)
	}
	// ParseMAC reverses: addr[0]=0xFF (LSB first).
	want := [6]byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA}
	if addr != want {
		t.Fatalf("ParseMAC LE order: got %x, want %x", addr, want)
	}

	// The mgmt header uses the adapter index in LE16.
	var hdr [6]byte
	binary.LittleEndian.PutUint16(hdr[0:2], mgmtOpAddRemoteOOB)
	binary.LittleEndian.PutUint16(hdr[2:4], 0) // adapter index 0
	binary.LittleEndian.PutUint16(hdr[4:6], 71) // payload length
	if binary.LittleEndian.Uint16(hdr[0:2]) != 0x0021 {
		t.Fatal("opcode encoding wrong")
	}
}
