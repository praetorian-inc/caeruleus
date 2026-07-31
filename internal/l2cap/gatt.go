package l2cap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// ATT opcodes for GATT discovery (Core Spec Vol 3 Part F). These complement
// the read/write opcodes in l2cap.go and drive a complete, host/BlueZ-independent
// GATT walk directly over the raw ATT channel: the device's TRUE handles,
// including the GAP (0x1800) / GATT (0x1801) services some BlueZ versions hide.
const (
	OpFindInfoRequest         = 0x04
	OpFindInfoResponse        = 0x05
	OpReadByTypeRequest       = 0x08
	OpReadByTypeResponse      = 0x09
	OpReadByGroupTypeRequest  = 0x10
	OpReadByGroupTypeResponse = 0x11
)

// GATT attribute-type UUIDs (16-bit) used as discovery group/type filters.
const (
	uuidPrimaryService = 0x2800
	uuidCharacteristic = 0x2803
)

// errAttNotFound is the ATT "Attribute Not Found" (0x0A) code that terminates
// each discovery sub-procedure normally (Core Spec Vol 3 Part G §4.4-4.7).
const errAttNotFound = 0x0A

// GATTService is one primary service discovered via Read By Group Type.
type GATTService struct {
	StartHandle uint16 `json:"start_handle"`
	EndHandle   uint16 `json:"end_handle"`
	UUID        string `json:"uuid"`
}

// GATTCharacteristic is one characteristic declaration discovered via Read By
// Type (type 0x2803). Properties is the raw ATT properties bitfield.
type GATTCharacteristic struct {
	DeclHandle  uint16 `json:"decl_handle"`
	ValueHandle uint16 `json:"value_handle"`
	Properties  uint8  `json:"properties"`
	UUID        string `json:"uuid"`
}

// GATTDescriptor is one attribute discovered via Find Information within a
// characteristic's handle range (CCCD, CEP, CUD, ...).
type GATTDescriptor struct {
	Handle uint16 `json:"handle"`
	UUID   string `json:"uuid"`
}

// uuidString renders little-endian on-the-wire UUID bytes (2 or 16) as a
// canonical lowercase string, matching BlueZ's form (e.g. a 16-bit 0x2A00
// becomes "00002a00-0000-1000-8000-00805f9b34fb").
func uuidString(b []byte) string {
	switch len(b) {
	case 2:
		return fmt.Sprintf("0000%04x-0000-1000-8000-00805f9b34fb", binary.LittleEndian.Uint16(b))
	case 16:
		var be [16]byte
		for i := 0; i < 16; i++ {
			be[i] = b[15-i] // wire is little-endian; canonical is big-endian
		}
		return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			be[0], be[1], be[2], be[3], be[4], be[5], be[6], be[7],
			be[8], be[9], be[10], be[11], be[12], be[13], be[14], be[15])
	default:
		return hex.EncodeToString(b)
	}
}

// parseReadByGroupType parses a Read By Group Type Response body (post-opcode):
// length(1) then repeated [attHandle(2), endGroupHandle(2), value(length-4)].
func parseReadByGroupType(body []byte) ([]GATTService, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("read-by-group-type: empty body")
	}
	l := int(body[0])
	uuidLen := l - 4
	if l < 6 || (uuidLen != 2 && uuidLen != 16) {
		return nil, fmt.Errorf("read-by-group-type: bad entry length %d", l)
	}
	rest := body[1:]
	var out []GATTService
	for len(rest) >= l {
		e := rest[:l]
		out = append(out, GATTService{
			StartHandle: binary.LittleEndian.Uint16(e[0:2]),
			EndHandle:   binary.LittleEndian.Uint16(e[2:4]),
			UUID:        uuidString(e[4:]),
		})
		rest = rest[l:]
	}
	return out, nil
}

// parseReadByType parses a Read By Type Response body for characteristic
// declarations: length(1) then repeated [declHandle(2), value(length-2)],
// where value = properties(1) + valueHandle(2) + charUUID(2|16).
func parseReadByType(body []byte) ([]GATTCharacteristic, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("read-by-type: empty body")
	}
	l := int(body[0])
	uuidLen := l - 2 - 3 // minus declHandle(2), props(1), valueHandle(2)
	if l < 7 || (uuidLen != 2 && uuidLen != 16) {
		return nil, fmt.Errorf("read-by-type: bad entry length %d", l)
	}
	rest := body[1:]
	var out []GATTCharacteristic
	for len(rest) >= l {
		e := rest[:l]
		val := e[2:]
		out = append(out, GATTCharacteristic{
			DeclHandle:  binary.LittleEndian.Uint16(e[0:2]),
			Properties:  val[0],
			ValueHandle: binary.LittleEndian.Uint16(val[1:3]),
			UUID:        uuidString(val[3:]),
		})
		rest = rest[l:]
	}
	return out, nil
}

// parseFindInfo parses a Find Information Response body: format(1) then
// repeated [handle(2), uuid(2|16)] (format 0x01 = 16-bit, 0x02 = 128-bit).
func parseFindInfo(body []byte) ([]GATTDescriptor, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("find-info: empty body")
	}
	var uuidLen int
	switch body[0] {
	case 0x01:
		uuidLen = 2
	case 0x02:
		uuidLen = 16
	default:
		return nil, fmt.Errorf("find-info: bad format 0x%02x", body[0])
	}
	pair := 2 + uuidLen
	rest := body[1:]
	var out []GATTDescriptor
	for len(rest) >= pair {
		e := rest[:pair]
		out = append(out, GATTDescriptor{
			Handle: binary.LittleEndian.Uint16(e[0:2]),
			UUID:   uuidString(e[2:]),
		})
		rest = rest[pair:]
	}
	return out, nil
}

// DiscoverPrimaryServices walks the whole ATT database via Read By Group Type
// (group type 0x2800), returning every primary service with its true handle
// range. Terminates on ATT "Attribute Not Found" or end-of-database.
func (c *Conn) DiscoverPrimaryServices(timeout time.Duration) ([]GATTService, error) {
	var svcs []GATTService
	start := uint16(0x0001)
	for {
		pdu := make([]byte, 7)
		pdu[0] = OpReadByGroupTypeRequest
		binary.LittleEndian.PutUint16(pdu[1:3], start)
		binary.LittleEndian.PutUint16(pdu[3:5], 0xFFFF)
		binary.LittleEndian.PutUint16(pdu[5:7], uuidPrimaryService)
		r, err := c.requestAndRead(pdu, OpReadByGroupTypeRequest, timeout)
		if err != nil {
			return svcs, err
		}
		if r.Opcode == OpErrorResponse {
			if r.ErrCode == errAttNotFound {
				break
			}
			return svcs, fmt.Errorf("service discovery: ATT error 0x%02x (%s)", r.ErrCode, attErrorString(r.ErrCode))
		}
		if r.Opcode != OpReadByGroupTypeResponse {
			return svcs, fmt.Errorf("service discovery: unexpected opcode 0x%02x", r.Opcode)
		}
		batch, err := parseReadByGroupType(r.Body)
		if err != nil {
			return svcs, err
		}
		if len(batch) == 0 {
			break
		}
		svcs = append(svcs, batch...)
		last := batch[len(batch)-1].EndHandle
		if last == 0xFFFF || last < start {
			break
		}
		start = last + 1
	}
	return svcs, nil
}

// DiscoverCharacteristics walks [start,end] via Read By Type (type 0x2803),
// returning every characteristic declaration with true declaration + value
// handles and the properties byte.
func (c *Conn) DiscoverCharacteristics(start, end uint16, timeout time.Duration) ([]GATTCharacteristic, error) {
	var chars []GATTCharacteristic
	cur := start
	for cur <= end {
		pdu := make([]byte, 7)
		pdu[0] = OpReadByTypeRequest
		binary.LittleEndian.PutUint16(pdu[1:3], cur)
		binary.LittleEndian.PutUint16(pdu[3:5], end)
		binary.LittleEndian.PutUint16(pdu[5:7], uuidCharacteristic)
		r, err := c.requestAndRead(pdu, OpReadByTypeRequest, timeout)
		if err != nil {
			return chars, err
		}
		if r.Opcode == OpErrorResponse {
			if r.ErrCode == errAttNotFound {
				break
			}
			return chars, fmt.Errorf("characteristic discovery: ATT error 0x%02x (%s)", r.ErrCode, attErrorString(r.ErrCode))
		}
		if r.Opcode != OpReadByTypeResponse {
			return chars, fmt.Errorf("characteristic discovery: unexpected opcode 0x%02x", r.Opcode)
		}
		batch, err := parseReadByType(r.Body)
		if err != nil {
			return chars, err
		}
		if len(batch) == 0 {
			break
		}
		chars = append(chars, batch...)
		last := batch[len(batch)-1].DeclHandle
		if last >= end || last < cur {
			break
		}
		cur = last + 1
	}
	return chars, nil
}

// DiscoverDescriptors walks [start,end] via Find Information, returning every
// attribute handle/UUID pair in the range (used per-characteristic to surface
// CCCDs and other descriptors).
func (c *Conn) DiscoverDescriptors(start, end uint16, timeout time.Duration) ([]GATTDescriptor, error) {
	if start > end {
		return nil, nil
	}
	var descs []GATTDescriptor
	cur := start
	for cur <= end {
		pdu := make([]byte, 5)
		pdu[0] = OpFindInfoRequest
		binary.LittleEndian.PutUint16(pdu[1:3], cur)
		binary.LittleEndian.PutUint16(pdu[3:5], end)
		r, err := c.requestAndRead(pdu, OpFindInfoRequest, timeout)
		if err != nil {
			return descs, err
		}
		if r.Opcode == OpErrorResponse {
			if r.ErrCode == errAttNotFound {
				break
			}
			return descs, fmt.Errorf("descriptor discovery: ATT error 0x%02x (%s)", r.ErrCode, attErrorString(r.ErrCode))
		}
		if r.Opcode != OpFindInfoResponse {
			return descs, fmt.Errorf("descriptor discovery: unexpected opcode 0x%02x", r.Opcode)
		}
		batch, err := parseFindInfo(r.Body)
		if err != nil {
			return descs, err
		}
		if len(batch) == 0 {
			break
		}
		descs = append(descs, batch...)
		last := batch[len(batch)-1].Handle
		if last >= end || last < cur {
			break
		}
		cur = last + 1
	}
	return descs, nil
}
