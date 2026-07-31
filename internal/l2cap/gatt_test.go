package l2cap

import "testing"

func TestUUIDString(t *testing.T) {
	if got := uuidString([]byte{0x00, 0x2A}); got != "00002a00-0000-1000-8000-00805f9b34fb" {
		t.Errorf("16-bit UUID: got %q", got)
	}
	// 128-bit: wire is little-endian, canonical is the byte-reversed form.
	wire := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if got := uuidString(wire); got != "0f0e0d0c-0b0a-0908-0706-050403020100" {
		t.Errorf("128-bit UUID: got %q", got)
	}
}

func TestParseReadByGroupType(t *testing.T) {
	// Two primary services: GAP 0x1800 @ 0x0001-0x0005, GATT 0x1801 @ 0x0006-0x0009.
	body := []byte{
		0x06, // entry length = 4 + 2-byte UUID
		0x01, 0x00, 0x05, 0x00, 0x00, 0x18,
		0x06, 0x00, 0x09, 0x00, 0x01, 0x18,
	}
	svcs, err := parseReadByGroupType(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(svcs) != 2 {
		t.Fatalf("want 2 services, got %d", len(svcs))
	}
	if svcs[0].StartHandle != 0x0001 || svcs[0].EndHandle != 0x0005 ||
		svcs[0].UUID != "00001800-0000-1000-8000-00805f9b34fb" {
		t.Errorf("svc0 = %+v", svcs[0])
	}
	if svcs[1].StartHandle != 0x0006 || svcs[1].EndHandle != 0x0009 ||
		svcs[1].UUID != "00001801-0000-1000-8000-00805f9b34fb" {
		t.Errorf("svc1 = %+v", svcs[1])
	}
}

func TestParseReadByType(t *testing.T) {
	// BLECTF Device Name char: decl 0x0014, props R (0x02), value handle 0x0015, UUID 0x2A00.
	body := []byte{
		0x07, // entry length = declHandle(2) + props(1) + valHandle(2) + UUID(2)
		0x14, 0x00, 0x02, 0x15, 0x00, 0x00, 0x2A,
	}
	chars, err := parseReadByType(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(chars) != 1 {
		t.Fatalf("want 1 char, got %d", len(chars))
	}
	c := chars[0]
	if c.DeclHandle != 0x0014 || c.ValueHandle != 0x0015 || c.Properties != 0x02 ||
		c.UUID != "00002a00-0000-1000-8000-00805f9b34fb" {
		t.Errorf("char = %+v", c)
	}
}

func TestParseReadByType128(t *testing.T) {
	// 128-bit custom char: decl 0x002a, props R|W (0x0a), value handle 0x002b.
	wire := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	body := append([]byte{
		0x15,             // entry length = 2 + 1 + 2 + 16 = 21
		0x2A, 0x00, 0x0A, 0x2B, 0x00,
	}, wire...)
	chars, err := parseReadByType(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(chars) != 1 || chars[0].Properties != 0x0A || chars[0].ValueHandle != 0x002B ||
		chars[0].UUID != "0f0e0d0c-0b0a-0908-0706-050403020100" {
		t.Errorf("char = %+v", chars[0])
	}
}

func TestParseFindInfo(t *testing.T) {
	// A CCCD (0x2902) at handle 0x0016, 16-bit format.
	body := []byte{0x01, 0x16, 0x00, 0x02, 0x29}
	descs, err := parseFindInfo(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(descs) != 1 || descs[0].Handle != 0x0016 ||
		descs[0].UUID != "00002902-0000-1000-8000-00805f9b34fb" {
		t.Errorf("desc = %+v", descs[0])
	}
	// 128-bit descriptor, format 0x02.
	wire := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	body2 := append([]byte{0x02, 0x20, 0x00}, wire...)
	d2, err := parseFindInfo(body2)
	if err != nil || len(d2) != 1 || d2[0].Handle != 0x0020 ||
		d2[0].UUID != "0f0e0d0c-0b0a-0908-0706-050403020100" {
		t.Errorf("128-bit desc = %+v err=%v", d2, err)
	}
}

func TestParseReadByGroupTypeBadLength(t *testing.T) {
	if _, err := parseReadByGroupType([]byte{0x03, 0x01, 0x00}); err == nil {
		t.Error("expected error on bad entry length")
	}
	if _, err := parseReadByGroupType(nil); err == nil {
		t.Error("expected error on empty body")
	}
}
