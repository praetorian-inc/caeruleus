// Package smp implements just enough of the Security Manager Protocol (Core
// Spec Vol 3 Part H) to drive the pairing Feature Exchange directly, over a
// raw HCI user channel. This bypasses BlueZ entirely (Linux handles SMP
// in-kernel, so a normal L2CAP socket on CID 0x0006 cannot), giving full
// control of the Pairing Request - which is what pairing-security testing
// (Just Works / key-size / legacy downgrade probing) needs.
//
// This file is the protocol codec: SMP PDU encode/decode with no I/O, so it is
// unit-testable without hardware.
package smp

import "fmt"

// SMP PDU opcodes (Vol 3 Part H 3.3).
const (
	OpPairingRequest    = 0x01
	OpPairingResponse   = 0x02
	OpPairingConfirm    = 0x03
	OpPairingRandom     = 0x04
	OpPairingFailed     = 0x05
	OpSecurityRequest   = 0x0b
	OpPairingPublicKey  = 0x0c
	OpPairingDHKeyCheck = 0x0d
)

// IO capability values (Vol 3 Part H 3.5.1).
const (
	IODisplayOnly     = 0x00
	IODisplayYesNo    = 0x01
	IOKeyboardOnly    = 0x02
	IONoInputNoOutput = 0x03
	IOKeyboardDisplay = 0x04
)

func IOCapName(c byte) string {
	switch c {
	case IODisplayOnly:
		return "DisplayOnly"
	case IODisplayYesNo:
		return "DisplayYesNo"
	case IOKeyboardOnly:
		return "KeyboardOnly"
	case IONoInputNoOutput:
		return "NoInputNoOutput"
	case IOKeyboardDisplay:
		return "KeyboardDisplay"
	default:
		return fmt.Sprintf("0x%02x", c)
	}
}

// AuthReq bit fields (Vol 3 Part H 3.5.1, Figure 3.3).
const (
	authBondingMask = 0x03 // bits 0-1
	authMITM        = 0x04 // bit 2
	authSC          = 0x08 // bit 3 (LE Secure Connections)
	authKeypress    = 0x10 // bit 4
	authCT2         = 0x20 // bit 5
)

// AuthReq is a decoded Authentication Requirements byte.
type AuthReq struct {
	Bonding  bool
	MITM     bool
	SC       bool // LE Secure Connections
	Keypress bool
}

func (a AuthReq) Byte() byte {
	var b byte
	if a.Bonding {
		b |= 0x01 // "Bonding"
	}
	if a.MITM {
		b |= authMITM
	}
	if a.SC {
		b |= authSC
	}
	if a.Keypress {
		b |= authKeypress
	}
	return b
}

func ParseAuthReq(b byte) AuthReq {
	return AuthReq{
		Bonding:  b&authBondingMask != 0,
		MITM:     b&authMITM != 0,
		SC:       b&authSC != 0,
		Keypress: b&authKeypress != 0,
	}
}

func (a AuthReq) String() string {
	s := "bonding="
	if a.Bonding {
		s += "yes"
	} else {
		s += "no"
	}
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	return fmt.Sprintf("%s mitm=%s sc=%s keypress=%s", s, yn(a.MITM), yn(a.SC), yn(a.Keypress))
}

// Key distribution flags (Vol 3 Part H 3.6.1).
const (
	KeyEnc  = 0x01 // LTK / EDIV+Rand (LE legacy) or LTK (LESC)
	KeyID   = 0x02 // IRK + identity address
	KeySign = 0x04 // CSRK
	KeyLink = 0x08 // Link Key (BR/EDR derivation)
)

// PairingPDU is a Pairing Request or Pairing Response (both share the layout).
type PairingPDU struct {
	IOCap       byte
	OOB         byte // 0 = not present, 1 = present
	AuthReq     AuthReq
	MaxKeySize  byte // 7..16
	InitKeyDist byte
	RespKeyDist byte
}

// Encode renders the PDU body for the given opcode (PairingRequest/Response):
// opcode, io, oob, authreq, maxkeysize, initkeydist, respkeydist (7 bytes).
func (p PairingPDU) Encode(opcode byte) []byte {
	return []byte{
		opcode,
		p.IOCap,
		p.OOB,
		p.AuthReq.Byte(),
		p.MaxKeySize,
		p.InitKeyDist,
		p.RespKeyDist,
	}
}

// ParsePairing decodes a Pairing Request/Response PDU (including the opcode
// byte). It returns the opcode and the parsed fields.
func ParsePairing(b []byte) (opcode byte, p PairingPDU, err error) {
	if len(b) < 7 {
		return 0, PairingPDU{}, fmt.Errorf("pairing PDU too short: %d bytes", len(b))
	}
	if b[0] != OpPairingRequest && b[0] != OpPairingResponse {
		return b[0], PairingPDU{}, fmt.Errorf("not a pairing req/rsp PDU: opcode 0x%02x", b[0])
	}
	return b[0], PairingPDU{
		IOCap:       b[1],
		OOB:         b[2],
		AuthReq:     ParseAuthReq(b[3]),
		MaxKeySize:  b[4],
		InitKeyDist: b[5],
		RespKeyDist: b[6],
	}, nil
}

// Pairing Failed reason codes (Vol 3 Part H 3.5.5, Table 3.7).
var failReasons = map[byte]string{
	0x01: "Passkey Entry Failed",
	0x02: "OOB Not Available",
	0x03: "Authentication Requirements",
	0x04: "Confirm Value Failed",
	0x05: "Pairing Not Supported",
	0x06: "Encryption Key Size",
	0x07: "Command Not Supported",
	0x08: "Unspecified Reason",
	0x09: "Repeated Attempts",
	0x0a: "Invalid Parameters",
	0x0b: "DHKey Check Failed",
	0x0c: "Numeric Comparison Failed",
	0x0d: "BR/EDR Pairing In Progress",
	0x0e: "Cross-transport Key Derivation Not Allowed",
	0x0f: "Key Rejected",
}

func FailReason(code byte) string {
	if s, ok := failReasons[code]; ok {
		return s
	}
	return fmt.Sprintf("reason 0x%02x", code)
}

// EncodeFailed renders a Pairing Failed PDU with the given reason code.
func EncodeFailed(reason byte) []byte { return []byte{OpPairingFailed, reason} }
