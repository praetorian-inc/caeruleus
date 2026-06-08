package smp

import "testing"

func TestAuthReqRoundTrip(t *testing.T) {
	cases := []AuthReq{
		{},
		{Bonding: true},
		{Bonding: true, MITM: true},
		{Bonding: true, MITM: true, SC: true},
		{Bonding: true, SC: true, Keypress: true},
	}
	for _, a := range cases {
		got := ParseAuthReq(a.Byte())
		if got != a {
			t.Errorf("AuthReq round-trip: %+v -> 0x%02x -> %+v", a, a.Byte(), got)
		}
	}
	// Known bit positions.
	if (AuthReq{MITM: true}).Byte() != 0x04 {
		t.Error("MITM bit should be 0x04")
	}
	if (AuthReq{SC: true}).Byte() != 0x08 {
		t.Error("SC bit should be 0x08")
	}
	if (AuthReq{Bonding: true}).Byte() != 0x01 {
		t.Error("Bonding should be 0x01")
	}
}

func TestPairingEncodeParse(t *testing.T) {
	p := PairingPDU{
		IOCap:       IONoInputNoOutput,
		OOB:         0,
		AuthReq:     AuthReq{Bonding: true, SC: true},
		MaxKeySize:  16,
		InitKeyDist: KeyEnc | KeyID,
		RespKeyDist: KeyEnc | KeyID,
	}
	enc := p.Encode(OpPairingRequest)
	if len(enc) != 7 || enc[0] != OpPairingRequest {
		t.Fatalf("encode: %x", enc)
	}
	op, got, err := ParsePairing(enc)
	if err != nil {
		t.Fatal(err)
	}
	if op != OpPairingRequest || got != p {
		t.Errorf("round-trip mismatch: op=0x%02x got=%+v want=%+v", op, got, p)
	}
}

func TestParsePairingRejects(t *testing.T) {
	if _, _, err := ParsePairing([]byte{OpPairingRequest, 0x00}); err == nil {
		t.Error("short PDU should error")
	}
	if _, _, err := ParsePairing([]byte{OpPairingFailed, 0x03, 0, 0, 0, 0, 0}); err == nil {
		t.Error("non-pairing opcode should error")
	}
}

func TestFailReason(t *testing.T) {
	if FailReason(0x05) != "Pairing Not Supported" {
		t.Error("0x05 should be Pairing Not Supported")
	}
	if FailReason(0x03) != "Authentication Requirements" {
		t.Error("0x03 should be Authentication Requirements")
	}
}
