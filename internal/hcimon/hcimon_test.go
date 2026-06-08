package hcimon

import "testing"

// frame wraps an HCI event payload in the kernel monitor header that
// parseConnEvent expects: opcode(2 LE) index(2 LE) plen(2 LE) | payload.
func frame(opcode, index uint16, payload []byte) []byte {
	b := []byte{
		byte(opcode), byte(opcode >> 8),
		byte(index), byte(index >> 8),
		byte(len(payload)), byte(len(payload) >> 8),
	}
	return append(b, payload...)
}

// leMetaEvent builds an HCI LE Meta event packet: event_code(0x3E) param_len params.
func leMetaEvent(params []byte) []byte {
	return append([]byte{hciEvtLEMeta, byte(len(params))}, params...)
}

func TestParseConnEvent_ConnectionComplete(t *testing.T) {
	// LE Connection Complete: status=0, handle=0x0040, role=0 (central),
	// peer_type=0, peer_addr=CC:B6:0E:3C:97:0B (wire order is little-endian),
	// interval=0x0018 (24 -> 30ms), latency=0, timeout=0x01F4 (500 -> 5000ms).
	params := []byte{
		leSubConnComplete, 0x00,
		0x40, 0x00, // handle
		0x00,                               // role: central
		0x00,                               // peer addr type: public
		0x0B, 0x97, 0x3C, 0x0E, 0xB6, 0xCC, // peer addr (LE)
		0x18, 0x00, // interval units
		0x00, 0x00, // latency
		0xF4, 0x01, // supervision timeout units
		0x00, // master clock accuracy
	}
	pkt := frame(monOpcodeEventPkt, 0, leMetaEvent(params))

	ev, ok := parseConnEvent(pkt)
	if !ok {
		t.Fatal("expected a parsed connection event")
	}
	if ev.Updated {
		t.Error("Connection Complete should not be marked Updated")
	}
	if ev.ConnHandle != 0x0040 {
		t.Errorf("conn handle = 0x%04x, want 0x0040", ev.ConnHandle)
	}
	if ev.Role != 0 {
		t.Errorf("role = %d, want 0 (central)", ev.Role)
	}
	if ev.PeerAddr != "CC:B6:0E:3C:97:0B" {
		t.Errorf("peer addr = %q, want CC:B6:0E:3C:97:0B", ev.PeerAddr)
	}
	if ev.IntervalMillis() != 30.0 {
		t.Errorf("interval = %.2fms, want 30.00ms", ev.IntervalMillis())
	}
	if ev.LatencyEvents != 0 {
		t.Errorf("latency = %d, want 0", ev.LatencyEvents)
	}
	if ev.TimeoutMillis() != 5000 {
		t.Errorf("supervision timeout = %dms, want 5000ms", ev.TimeoutMillis())
	}
}

func TestParseConnEvent_ConnectionUpdate(t *testing.T) {
	// LE Connection Update Complete: handle=0x0040, interval=0x0028 (40 -> 50ms),
	// latency=4, timeout=0x02BC (700 -> 7000ms). No peer address in this event.
	params := []byte{
		leSubConnUpdate, 0x00,
		0x40, 0x00, // handle
		0x28, 0x00, // interval
		0x04, 0x00, // latency
		0xBC, 0x02, // timeout
	}
	pkt := frame(monOpcodeEventPkt, 0, leMetaEvent(params))

	ev, ok := parseConnEvent(pkt)
	if !ok {
		t.Fatal("expected a parsed connection update event")
	}
	if !ev.Updated {
		t.Error("Connection Update Complete should be marked Updated")
	}
	if ev.ConnHandle != 0x0040 {
		t.Errorf("conn handle = 0x%04x, want 0x0040", ev.ConnHandle)
	}
	if ev.PeerAddr != "" {
		t.Errorf("update event should carry no peer addr, got %q", ev.PeerAddr)
	}
	if ev.IntervalMillis() != 50.0 {
		t.Errorf("interval = %.2fms, want 50.00ms", ev.IntervalMillis())
	}
	if ev.LatencyEvents != 4 {
		t.Errorf("latency = %d, want 4", ev.LatencyEvents)
	}
	if ev.TimeoutMillis() != 7000 {
		t.Errorf("supervision timeout = %dms, want 7000ms", ev.TimeoutMillis())
	}
}

func TestParseConnEvent_Rejects(t *testing.T) {
	cases := map[string][]byte{
		"non-event opcode":     frame(monOpcodeACLRxPkt, 0, leMetaEvent([]byte{leSubConnComplete, 0x00})),
		"non-LE-meta event":    frame(monOpcodeEventPkt, 0, []byte{0x0E, 0x01, 0x00}),
		"truncated conn-compl": frame(monOpcodeEventPkt, 0, leMetaEvent([]byte{leSubConnComplete, 0x00, 0x40})),
		"unknown subevent":     frame(monOpcodeEventPkt, 0, leMetaEvent([]byte{0x7F, 0x00})),
		"short frame":          {0x03, 0x00},
	}
	for name, pkt := range cases {
		if _, ok := parseConnEvent(pkt); ok {
			t.Errorf("%s: expected rejection, got a parsed event", name)
		}
	}
}
