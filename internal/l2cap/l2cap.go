// Package l2cap opens a raw L2CAP socket on the ATT fixed channel
// (CID 0x0004) toward an LE peer, so we can ship ATT PDUs that BlueZ
// either won't (write to a hidden CCCD, signed writes, prepared writes
// for fuzzing) or can't (handles BlueZ doesn't expose as descriptor
// objects).
//
// The socket coexists with BlueZ when BlueZ has the LE link up: the
// kernel routes ATT PDUs on CID 0x0004 to/from any userspace L2CAP
// socket attached to the same connection. The trade-off is that BlueZ's
// internal ATT handler may simultaneously be sending its own PDUs on
// the same channel; the kernel does NOT enforce ATT request/response
// pairing, so an in-flight BlueZ read could pick up our response (or
// vice versa). For one-shot writes-with-response on a handle BlueZ
// isn't actively probing, the interleaving risk is low.
//
// Requires CAP_NET_RAW or root.
package l2cap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// AttCID is the fixed L2CAP channel ID for the Attribute Protocol on
	// LE links. Always present once the LE ACL link is up; no PSM
	// negotiation required.
	AttCID = 0x0004

	// Address-type values from <bluetooth/bluetooth.h>.
	BDADDRLEPublic = 1
	BDADDRLERandom = 2

	// ATT opcodes — Core Spec Vol 3 Part F.
	OpErrorResponse           = 0x01
	OpWriteRequest            = 0x12
	OpWriteResponse           = 0x13
	OpPrepareWriteRequest     = 0x16
	OpPrepareWriteResponse    = 0x17
	OpExecuteWriteRequest     = 0x18
	OpExecuteWriteResponse    = 0x19
	OpWriteCommand            = 0x52
	OpHandleValueNotification = 0x1B
	OpHandleValueIndication   = 0x1D
	OpHandleValueConfirmation = 0x1E

	// Execute Write flags (Core Spec Vol 3 Part F §3.4.6).
	ExecFlagCancel = 0x00
	ExecFlagCommit = 0x01
)

// Conn is an open L2CAP socket bound to the ATT channel of a single LE
// connection. Close it when done.
type Conn struct {
	fd     int
	closed bool
}

// Dial connects to peer on CID 0x0004. peer is in human-readable order:
// the first byte is what you'd write at the left of an "AA:BB:..." MAC
// string. The kernel reverses internally for the wire little-endian form.
//
// peerAddrType is BDADDRLEPublic or BDADDRLERandom — usually Public for
// most off-the-shelf peripherals.
func Dial(peer [6]byte, peerAddrType uint8) (*Conn, error) {
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, unix.BTPROTO_L2CAP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("AF_BLUETOOTH socket: %w (run with sudo)", err)
		}
		return nil, fmt.Errorf("AF_BLUETOOTH socket: %w", err)
	}

	// Bind to any local LE address on the ATT CID.
	if err := unix.Bind(fd, &unix.SockaddrL2{CID: AttCID, AddrType: BDADDRLEPublic}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind L2CAP local on CID 0x%04x: %w", AttCID, err)
	}

	if err := unix.Connect(fd, &unix.SockaddrL2{
		CID:      AttCID,
		Addr:     peer,
		AddrType: peerAddrType,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("connect L2CAP ATT to %02X:%02X:%02X:%02X:%02X:%02X: %w "+
			"(if BlueZ has no active LE link, run a BlueZ command first to bring it up; "+
			"if BlueZ does and this still fails, the kernel may not allow a second socket "+
			"on the same CID — fall back to HCI_CHANNEL_USER or stop bluetoothd)",
			peer[0], peer[1], peer[2], peer[3], peer[4], peer[5], err)
	}
	return &Conn{fd: fd}, nil
}

// Close releases the L2CAP socket. Idempotent.
func (c *Conn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return unix.Close(c.fd)
}

// WriteRequest sends ATT Write Request (opcode 0x12) and parses the
// matching Write Response (0x13) or Error Response (0x01). timeout
// caps the response wait; SO_RCVTIMEO is set on the socket so a missing
// response doesn't hang forever.
func (c *Conn) WriteRequest(handle uint16, value []byte, timeout time.Duration) error {
	pdu := make([]byte, 3+len(value))
	pdu[0] = OpWriteRequest
	binary.LittleEndian.PutUint16(pdu[1:3], handle)
	copy(pdu[3:], value)

	if _, err := unix.Write(c.fd, pdu); err != nil {
		return fmt.Errorf("ATT Write Request send: %w", err)
	}

	if timeout > 0 {
		tv := unix.Timeval{Sec: int64(timeout / time.Second), Usec: int64((timeout % time.Second) / time.Microsecond)}
		_ = unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	}

	buf := make([]byte, 64)
	n, err := unix.Read(c.fd, buf)
	if err != nil {
		return fmt.Errorf("ATT Write Request response read: %w", err)
	}
	if n < 1 {
		return errors.New("ATT Write Request: empty response")
	}
	switch buf[0] {
	case OpWriteResponse:
		return nil
	case OpErrorResponse:
		if n < 5 {
			return fmt.Errorf("ATT Error Response truncated (%d bytes)", n)
		}
		reqOp := buf[1]
		errHnd := binary.LittleEndian.Uint16(buf[2:4])
		code := buf[4]
		return fmt.Errorf("ATT Error Response: req-opcode=0x%02x handle=0x%04x code=0x%02x (%s)",
			reqOp, errHnd, code, attErrorString(code))
	default:
		return fmt.Errorf("ATT Write Request: unexpected response opcode 0x%02x", buf[0])
	}
}

// WriteCommand sends ATT Write Command (opcode 0x52) — write without
// response. No reply expected; returns once the kernel accepts the send.
func (c *Conn) WriteCommand(handle uint16, value []byte) error {
	pdu := make([]byte, 3+len(value))
	pdu[0] = OpWriteCommand
	binary.LittleEndian.PutUint16(pdu[1:3], handle)
	copy(pdu[3:], value)
	if _, err := unix.Write(c.fd, pdu); err != nil {
		return fmt.Errorf("ATT Write Command send: %w", err)
	}
	return nil
}

// Response is a structured ATT response from a request-type opcode. Used
// by the fuzzing engine to distinguish "ATT Error Response" (interesting
// data, not a failure) from "no response at all" (transport problem).
type Response struct {
	Opcode  uint8  // OpWriteResponse / OpPrepareWriteResponse / OpExecuteWriteResponse / OpErrorResponse
	ErrCode uint8  // when Opcode == OpErrorResponse
	ReqOp   uint8  // the opcode the peripheral is reporting on (Error Response only)
	Handle  uint16 // the handle in question (Error Response only)
	Body    []byte // response PDU body, post-opcode (for Prepare Write Response = the echoed write)
}

// AttErrorString exposes the Core-Spec code → name mapping for callers
// that want to log a human-readable form alongside the numeric code.
func AttErrorString(code uint8) string { return attErrorString(code) }

// WriteRequestEx is the structured-response variant of WriteRequest.
// Transport errors (socket dead, timeout) return err != nil; an ATT
// Error Response is a successful return with Response.Opcode ==
// OpErrorResponse, which is what the fuzzer wants — an error code from
// the peripheral is signal, not failure.
func (c *Conn) WriteRequestEx(handle uint16, value []byte, timeout time.Duration) (Response, error) {
	pdu := make([]byte, 3+len(value))
	pdu[0] = OpWriteRequest
	binary.LittleEndian.PutUint16(pdu[1:3], handle)
	copy(pdu[3:], value)
	return c.requestAndRead(pdu, OpWriteRequest, timeout)
}

// PrepareWrite sends ATT Prepare Write Request (0x16). The peripheral
// queues (handle, offset, value) and echoes it back in the Prepare Write
// Response — the response Body is the echoed write. Multiple Prepare
// Writes can accumulate before an Execute Write commits or cancels them.
func (c *Conn) PrepareWrite(handle uint16, offset uint16, value []byte, timeout time.Duration) (Response, error) {
	pdu := make([]byte, 5+len(value))
	pdu[0] = OpPrepareWriteRequest
	binary.LittleEndian.PutUint16(pdu[1:3], handle)
	binary.LittleEndian.PutUint16(pdu[3:5], offset)
	copy(pdu[5:], value)
	return c.requestAndRead(pdu, OpPrepareWriteRequest, timeout)
}

// ExecuteWrite sends ATT Execute Write Request (0x18) with flags = 0x00
// (cancel) or 0x01 (commit). The peripheral applies (or discards) the
// previously-queued Prepare Writes and replies with an Execute Write
// Response (or an Error Response).
func (c *Conn) ExecuteWrite(flags uint8, timeout time.Duration) (Response, error) {
	pdu := []byte{OpExecuteWriteRequest, flags}
	return c.requestAndRead(pdu, OpExecuteWriteRequest, timeout)
}

// requestAndRead sends pdu, then reads up to MaxRespSize bytes back and
// parses the response. expectReq is the opcode being sent — used only
// for the diagnostic in the "unexpected response" path.
func (c *Conn) requestAndRead(pdu []byte, expectReq uint8, timeout time.Duration) (Response, error) {
	if _, err := unix.Write(c.fd, pdu); err != nil {
		return Response{}, fmt.Errorf("ATT request 0x%02x send: %w", expectReq, err)
	}
	if timeout > 0 {
		tv := unix.Timeval{Sec: int64(timeout / time.Second), Usec: int64((timeout % time.Second) / time.Microsecond)}
		_ = unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	}
	buf := make([]byte, 512)
	n, err := unix.Read(c.fd, buf)
	if err != nil {
		return Response{}, fmt.Errorf("ATT request 0x%02x response read: %w", expectReq, err)
	}
	if n < 1 {
		return Response{}, errors.New("ATT response: empty")
	}
	r := Response{Opcode: buf[0]}
	switch buf[0] {
	case OpErrorResponse:
		if n < 5 {
			return Response{}, fmt.Errorf("ATT Error Response truncated (%d bytes)", n)
		}
		r.ReqOp = buf[1]
		r.Handle = binary.LittleEndian.Uint16(buf[2:4])
		r.ErrCode = buf[4]
		return r, nil
	case OpWriteResponse, OpExecuteWriteResponse:
		// no body
		return r, nil
	case OpPrepareWriteResponse:
		if n > 1 {
			r.Body = append([]byte(nil), buf[1:n]...)
		}
		return r, nil
	default:
		if n > 1 {
			r.Body = append([]byte(nil), buf[1:n]...)
		}
		return r, nil
	}
}

// attErrorString maps an ATT error code byte to its Core-Spec name.
// Useful for diagnostic output; the numeric code stays in the error chain.
func attErrorString(code uint8) string {
	switch code {
	case 0x01:
		return "Invalid Handle"
	case 0x02:
		return "Read Not Permitted"
	case 0x03:
		return "Write Not Permitted"
	case 0x04:
		return "Invalid PDU"
	case 0x05:
		return "Insufficient Authentication"
	case 0x06:
		return "Request Not Supported"
	case 0x07:
		return "Invalid Offset"
	case 0x08:
		return "Insufficient Authorization"
	case 0x09:
		return "Prepare Queue Full"
	case 0x0A:
		return "Attribute Not Found"
	case 0x0B:
		return "Attribute Not Long"
	case 0x0C:
		return "Insufficient Encryption Key Size"
	case 0x0D:
		return "Invalid Attribute Value Length"
	case 0x0E:
		return "Unlikely Error"
	case 0x0F:
		return "Insufficient Encryption"
	case 0x10:
		return "Unsupported Group Type"
	case 0x11:
		return "Insufficient Resources"
	}
	if code >= 0x80 {
		return "Application Error (driver-specific)"
	}
	return "Unknown"
}
