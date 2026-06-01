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
	OpWriteCommand            = 0x52
	OpHandleValueNotification = 0x1B
	OpHandleValueIndication   = 0x1D
	OpHandleValueConfirmation = 0x1E
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
