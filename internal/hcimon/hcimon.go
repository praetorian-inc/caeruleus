// Package hcimon opens the kernel's HCI_CHANNEL_MONITOR socket and decodes
// inbound ATT notification / indication PDUs from the raw HCI traffic.
//
// This is the same interface btmon(1) uses. With it caeruleus can observe
// notifications that BlueZ's D-Bus layer hides — for example notifications
// pushed by a peripheral on a characteristic that does not advertise the
// NOTIFY property bit, or immediate-fire notifications that race past
// PropertiesChanged subscribers.
//
// Requires CAP_NET_RAW + CAP_NET_ADMIN (or root). Open() returns a clear
// error when the socket cannot be created.
package hcimon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// BTPROTO_HCI is the protocol number for raw HCI sockets on AF_BLUETOOTH.
	// Defined in <bluetooth/bluetooth.h>; not exported from x/sys/unix.
	BTPROTO_HCI = 1

	// Channel for HCI_DEV_NONE-bound sockets. The values come from
	// <bluetooth/hci.h>: HCI_CHANNEL_MONITOR=2, HCI_CHANNEL_CONTROL=3.
	HCI_CHANNEL_MONITOR = 2

	// HCI_DEV_NONE is used as the sockaddr_hci.dev when binding a control
	// or monitor socket; per-device sockets use the index instead.
	HCI_DEV_NONE = 0xFFFF

	// Monitor header opcodes — see kernel net/bluetooth/hci_sock.c.
	monOpcodeNewIndex   = 0x0000
	monOpcodeDelIndex   = 0x0001
	monOpcodeCommandPkt = 0x0002
	monOpcodeEventPkt   = 0x0003
	monOpcodeACLTxPkt   = 0x0004
	monOpcodeACLRxPkt   = 0x0005
	monOpcodeSCOTxPkt   = 0x0006
	monOpcodeSCORxPkt   = 0x0007
	monOpcodeOpenIndex  = 0x0008
	monOpcodeCloseIndex = 0x0009

	// ATT opcodes we extract — Core Spec Vol 3 Part F.
	ATTOpNotification = 0x1B
	ATTOpIndication   = 0x1D

	// L2CAP CID for the Attribute Protocol fixed channel.
	cidATT = 0x0004

	// HCI event decoding — Core Spec Vol 4 Part E. The LE Meta event (0x3E)
	// carries the LE subevents we use to recover connection parameters that
	// BlueZ does not surface over D-Bus.
	hciEvtLEMeta         = 0x3E
	leSubConnComplete    = 0x01
	leSubConnUpdate      = 0x03
	leSubEnhConnComplete = 0x0A
)

// Notification is a parsed inbound ATT Handle Value Notification or Indication.
type Notification struct {
	When       time.Time
	Adapter    uint16 // HCI device index (hci0 = 0)
	ConnHandle uint16 // ACL connection handle (peripheral identity in this session)
	AttHandle  uint16 // remote ATT handle the value is from
	Value      []byte
	IsIndicate bool // true when carried by 0x1D
}

// Monitor wraps an open HCI monitor socket.
type Monitor struct {
	fd     int
	closed bool
}

// Open creates a new HCI monitor socket and binds it to the monitor channel.
// It returns a friendly error when permissions are insufficient.
func Open() (*Monitor, error) {
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, BTPROTO_HCI)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("AF_BLUETOOTH raw socket: %w (run caeruleus with sudo)", err)
		}
		return nil, fmt.Errorf("AF_BLUETOOTH raw socket: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set nonblock: %w", err)
	}
	sa := &unix.SockaddrHCI{
		Dev:     HCI_DEV_NONE,
		Channel: HCI_CHANNEL_MONITOR,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("bind monitor channel: %w (run caeruleus with sudo)", err)
		}
		return nil, fmt.Errorf("bind monitor channel: %w", err)
	}
	return &Monitor{fd: fd}, nil
}

// Close releases the underlying file descriptor.
func (m *Monitor) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	return unix.Close(m.fd)
}

// Run reads from the monitor socket and pushes every parsed notification /
// indication to out. It returns when ctx is canceled, when out is closed by
// the caller (it isn't), or when an unrecoverable error happens on the
// socket. out is closed before Run returns.
func (m *Monitor) Run(ctx context.Context, out chan<- Notification) error {
	defer close(out)
	return m.readLoop(ctx, func(pkt []byte) bool {
		note, ok := parsePacket(pkt)
		if !ok {
			return true
		}
		select {
		case out <- note:
			return true
		case <-ctx.Done():
			return false
		}
	})
}

// RunConn reads from the monitor socket and pushes every parsed LE connection
// event (Connection Complete / Enhanced Connection Complete / Connection
// Update Complete) to out. Same lifecycle as Run: out is closed before return.
// This is how connection parameters (interval / latency / supervision timeout)
// are recovered — BlueZ does not expose them over D-Bus.
func (m *Monitor) RunConn(ctx context.Context, out chan<- ConnEvent) error {
	defer close(out)
	return m.readLoop(ctx, func(pkt []byte) bool {
		ev, ok := parseConnEvent(pkt)
		if !ok {
			return true
		}
		select {
		case out <- ev:
			return true
		case <-ctx.Done():
			return false
		}
	})
}

// readLoop polls the monitor socket and hands each raw frame to onFrame.
// onFrame returns false to stop the loop (used when a downstream send races
// a canceled context). The loop also stops on ctx cancellation or a fatal
// socket error.
func (m *Monitor) readLoop(ctx context.Context, onFrame func(pkt []byte) bool) error {
	buf := make([]byte, 4096)
	pfd := []unix.PollFd{{Fd: int32(m.fd), Events: unix.POLLIN}}

	for {
		if ctx.Err() != nil {
			return nil
		}
		// 200ms poll timeout so we re-check ctx promptly.
		n, err := unix.Poll(pfd, 200)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll: %w", err)
		}
		if n == 0 {
			continue
		}
		if pfd[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return fmt.Errorf("monitor socket closed (revents=0x%x)", pfd[0].Revents)
		}

		rn, err := unix.Read(m.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("read: %w", err)
		}
		if rn <= 0 {
			continue
		}
		if !onFrame(buf[:rn]) {
			return nil
		}
	}
}

// parsePacket decodes a single HCI monitor frame and returns the embedded
// ATT notification or indication if it carries one. Anything else is silently
// skipped.
func parsePacket(pkt []byte) (Notification, bool) {
	if len(pkt) < 6 {
		return Notification{}, false
	}
	opcode := binary.LittleEndian.Uint16(pkt[0:2])
	index := binary.LittleEndian.Uint16(pkt[2:4])
	plen := binary.LittleEndian.Uint16(pkt[4:6])
	if int(6+plen) > len(pkt) {
		return Notification{}, false
	}
	payload := pkt[6 : 6+plen]

	// We only care about RX ACL frames (peripheral -> host).
	if opcode != monOpcodeACLRxPkt {
		return Notification{}, false
	}
	return parseACL(payload, index)
}

// parseACL extracts an ATT notify/indicate from a raw HCI ACL packet. This
// handles only first-fragment / non-fragmented frames — typical notifications
// fit in a single ACL packet on BLE (ATT MTU defaults to 23, ACL data length
// is much larger), so reassembly is not required for the common case.
func parseACL(acl []byte, index uint16) (Notification, bool) {
	if len(acl) < 4 {
		return Notification{}, false
	}
	hf := binary.LittleEndian.Uint16(acl[0:2])
	connHandle := hf & 0x0FFF
	// pb bits (bits 12-13) tell us first/continuation. We only accept first.
	pb := (hf >> 12) & 0x3
	if pb != 0x02 && pb != 0x00 {
		// 0x02 = start of non-automatic-flush, 0x00 is also a start in BLE.
		return Notification{}, false
	}
	dlen := binary.LittleEndian.Uint16(acl[2:4])
	if int(4+dlen) > len(acl) {
		return Notification{}, false
	}
	payload := acl[4 : 4+dlen]
	if len(payload) < 4 {
		return Notification{}, false
	}
	// L2CAP header.
	cid := binary.LittleEndian.Uint16(payload[2:4])
	if cid != cidATT {
		return Notification{}, false
	}
	att := payload[4:]
	if len(att) < 3 {
		return Notification{}, false
	}
	op := att[0]
	if op != ATTOpNotification && op != ATTOpIndication {
		return Notification{}, false
	}
	attHnd := binary.LittleEndian.Uint16(att[1:3])
	value := append([]byte(nil), att[3:]...) // copy out of the read buffer
	return Notification{
		When:       time.Now(),
		Adapter:    index,
		ConnHandle: connHandle,
		AttHandle:  attHnd,
		Value:      value,
		IsIndicate: op == ATTOpIndication,
	}, true
}

// ConnEvent is a parsed LE connection-parameter event. It comes either from
// the initial Connection Complete (Updated=false, PeerAddr populated) or a
// later Connection Update Complete (Updated=true, PeerAddr empty — the event
// is keyed only by connection handle, so callers correlate on ConnHandle).
//
// The raw interval / latency / timeout are in HCI units; the helper methods
// convert to human terms (interval 1.25ms/unit, supervision timeout 10ms/unit,
// latency is a dimensionless count of connection events the peripheral may skip).
type ConnEvent struct {
	When          time.Time
	Adapter       uint16 // HCI device index (hci0 = 0)
	ConnHandle    uint16
	Updated       bool   // false = Connection Complete, true = Connection Update Complete
	Status        uint8  // HCI status (0 = success)
	Role          uint8  // 0 = central/master, 1 = peripheral/slave
	PeerAddrType  uint8  // 0 = public, 1 = random
	PeerAddr      string // "AA:BB:CC:DD:EE:FF" (MSB-first); empty on update events
	IntervalUnits uint16
	LatencyEvents uint16
	TimeoutUnits  uint16
}

// IntervalMillis returns the connection interval in milliseconds (1.25ms/unit).
func (e ConnEvent) IntervalMillis() float64 { return float64(e.IntervalUnits) * 1.25 }

// TimeoutMillis returns the supervision timeout in milliseconds (10ms/unit).
func (e ConnEvent) TimeoutMillis() int { return int(e.TimeoutUnits) * 10 }

// parseConnEvent decodes an LE Meta connection event from a monitor frame.
// Anything that is not an LE Connection Complete / Enhanced Connection
// Complete / Connection Update Complete is silently skipped.
func parseConnEvent(pkt []byte) (ConnEvent, bool) {
	if len(pkt) < 6 {
		return ConnEvent{}, false
	}
	opcode := binary.LittleEndian.Uint16(pkt[0:2])
	index := binary.LittleEndian.Uint16(pkt[2:4])
	plen := binary.LittleEndian.Uint16(pkt[4:6])
	if int(6+plen) > len(pkt) {
		return ConnEvent{}, false
	}
	payload := pkt[6 : 6+plen]

	// Host-bound HCI Event packet only.
	if opcode != monOpcodeEventPkt {
		return ConnEvent{}, false
	}
	// Event header: event_code(1), param_len(1), params...
	if len(payload) < 2 || payload[0] != hciEvtLEMeta {
		return ConnEvent{}, false
	}
	params := payload[2:]
	if len(params) < 1 {
		return ConnEvent{}, false
	}
	ev := ConnEvent{When: time.Now(), Adapter: index}
	switch params[0] { // LE subevent code
	case leSubConnComplete:
		// subevent(1) status(1) handle(2) role(1) peer_type(1) peer_addr(6)
		// interval(2) latency(2) timeout(2) clock_accuracy(1) = 19 bytes
		if len(params) < 19 {
			return ConnEvent{}, false
		}
		ev.Status = params[1]
		ev.ConnHandle = binary.LittleEndian.Uint16(params[2:4]) & 0x0FFF
		ev.Role = params[4]
		ev.PeerAddrType = params[5]
		ev.PeerAddr = addrFromLE(params[6:12])
		ev.IntervalUnits = binary.LittleEndian.Uint16(params[12:14])
		ev.LatencyEvents = binary.LittleEndian.Uint16(params[14:16])
		ev.TimeoutUnits = binary.LittleEndian.Uint16(params[16:18])
	case leSubEnhConnComplete:
		// Same as above but with local_rpa(6) + peer_rpa(6) inserted after
		// peer_addr, pushing the parameters to offset 24.
		if len(params) < 31 {
			return ConnEvent{}, false
		}
		ev.Status = params[1]
		ev.ConnHandle = binary.LittleEndian.Uint16(params[2:4]) & 0x0FFF
		ev.Role = params[4]
		ev.PeerAddrType = params[5]
		ev.PeerAddr = addrFromLE(params[6:12])
		ev.IntervalUnits = binary.LittleEndian.Uint16(params[24:26])
		ev.LatencyEvents = binary.LittleEndian.Uint16(params[26:28])
		ev.TimeoutUnits = binary.LittleEndian.Uint16(params[28:30])
	case leSubConnUpdate:
		// subevent(1) status(1) handle(2) interval(2) latency(2) timeout(2) = 10 bytes
		if len(params) < 10 {
			return ConnEvent{}, false
		}
		ev.Status = params[1]
		ev.ConnHandle = binary.LittleEndian.Uint16(params[2:4]) & 0x0FFF
		ev.Updated = true
		ev.IntervalUnits = binary.LittleEndian.Uint16(params[4:6])
		ev.LatencyEvents = binary.LittleEndian.Uint16(params[6:8])
		ev.TimeoutUnits = binary.LittleEndian.Uint16(params[8:10])
	default:
		return ConnEvent{}, false
	}
	return ev, true
}

// addrFromLE renders a little-endian 6-byte BD_ADDR (HCI wire order) as the
// conventional MSB-first colon string.
func addrFromLE(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		b[5], b[4], b[3], b[2], b[1], b[0])
}
