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

		if note, ok := parsePacket(buf[:rn]); ok {
			select {
			case out <- note:
			case <-ctx.Done():
				return nil
			}
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
