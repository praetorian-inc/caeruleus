// Package bdaddr handles reading and (best-effort) rewriting the local
// controller's Bluetooth address.
//
// Reading goes through BlueZ's Management API on HCI_CHANNEL_CONTROL, which
// is unrestricted by the kernel.
//
// Writing uses vendor-specific HCI commands (OGF 0x3F) on HCI_CHANNEL_RAW.
// Modern kernels (5.x+) only permit OGF=0x3F commands on raw HCI sockets;
// other commands return EPERM. Each chip vendor has its own opcode and
// payload format for "write BD_ADDR"; we ship a table of the common ones.
package bdaddr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	btprotoHCI         = 1
	hciChannelRaw      = 0
	hciChannelControl  = 3
	hciDevNone         = 0xFFFF
	hciCommandPkt      = 0x01
	hciEventPkt        = 0x04
	hciEvCmdComplete   = 0x0E
	hciEvCmdStatus     = 0x0F
	hciEvVendor        = 0xFF
	mgmtHdrLen         = 6
	mgmtOpReadInfo     = 0x0004
	mgmtEvCmdComplete  = 0x0001
	mgmtEvCmdStatus    = 0x0002
	mgmtEvCtrlIndexAdd = 0x0004
)

// ParseMAC accepts XX:XX:XX:XX:XX:XX (case-insensitive) and returns the bytes
// in little-endian order (LSB-first, as required by HCI commands).
func ParseMAC(s string) ([6]byte, error) {
	var out [6]byte
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return out, fmt.Errorf("BD_ADDR %q is not six colon-separated octets", s)
	}
	for i, p := range parts {
		var b byte
		if _, err := fmt.Sscanf(p, "%02x", &b); err != nil {
			return out, fmt.Errorf("BD_ADDR octet %q: %w", p, err)
		}
		out[5-i] = b // LE order
	}
	return out, nil
}

// ControllerInfo is the relevant subset of MGMT Read Controller Info.
type ControllerInfo struct {
	Address          string // big-endian XX:XX:... form
	Manufacturer     uint16
	ManufacturerName string
	BluetoothVersion uint8
	Settings         []string
}

// Manager holds an open MGMT API socket. Close when done.
type Manager struct {
	fd       int
	adapter  uint16
	closed   bool
}

// OpenManager dials HCI_CHANNEL_CONTROL for read-only operations on adapter idx.
func OpenManager(idx uint16) (*Manager, error) {
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, btprotoHCI)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("AF_BLUETOOTH raw socket: %w (sudo required)", err)
		}
		return nil, fmt.Errorf("AF_BLUETOOTH raw socket: %w", err)
	}
	sa := &unix.SockaddrHCI{Dev: hciDevNone, Channel: hciChannelControl}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("bind HCI_CHANNEL_CONTROL: %w (sudo required)", err)
		}
		return nil, fmt.Errorf("bind HCI_CHANNEL_CONTROL: %w", err)
	}
	return &Manager{fd: fd, adapter: idx}, nil
}

func (m *Manager) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	return unix.Close(m.fd)
}

// ReadControllerInfo sends MGMT_OP_READ_INFO (0x0004) and returns the parsed
// fields we care about for BD_ADDR work.
func (m *Manager) ReadControllerInfo() (*ControllerInfo, error) {
	if err := m.sendMgmt(mgmtOpReadInfo, nil); err != nil {
		return nil, err
	}
	resp, err := m.waitCmdComplete(mgmtOpReadInfo, 2*time.Second)
	if err != nil {
		return nil, err
	}
	if len(resp) < 6+1+2+4+4+3+249+11 {
		return nil, fmt.Errorf("Read Controller Info response is %d bytes, expected >= %d", len(resp), 6+1+2+4+4+3+249+11)
	}
	var addr [6]byte
	copy(addr[:], resp[0:6])
	macBE := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", addr[5], addr[4], addr[3], addr[2], addr[1], addr[0])
	btVer := resp[6]
	manuf := binary.LittleEndian.Uint16(resp[7:9])
	supported := binary.LittleEndian.Uint32(resp[9:13])
	current := binary.LittleEndian.Uint32(resp[13:17])

	return &ControllerInfo{
		Address:          macBE,
		BluetoothVersion: btVer,
		Manufacturer:     manuf,
		ManufacturerName: manufacturerName(manuf),
		Settings:         describeSettings(supported, current),
	}, nil
}

// sendMgmt writes a single MGMT command (opcode, index, payload).
func (m *Manager) sendMgmt(op uint16, payload []byte) error {
	buf := make([]byte, mgmtHdrLen+len(payload))
	binary.LittleEndian.PutUint16(buf[0:2], op)
	binary.LittleEndian.PutUint16(buf[2:4], m.adapter)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(payload)))
	copy(buf[6:], payload)
	_, err := unix.Write(m.fd, buf)
	return err
}

// waitCmdComplete blocks until an MGMT Command Complete event for op arrives
// (or the deadline expires). Returns the post-status payload bytes.
func (m *Manager) waitCmdComplete(op uint16, max time.Duration) ([]byte, error) {
	deadline := time.Now().Add(max)
	if err := unix.SetNonblock(m.fd, true); err != nil {
		return nil, err
	}
	pfd := []unix.PollFd{{Fd: int32(m.fd), Events: unix.POLLIN}}
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		left := time.Until(deadline)
		ms := int(left / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		n, err := unix.Poll(pfd, ms)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if n == 0 {
			continue
		}
		rn, err := unix.Read(m.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) {
				continue
			}
			return nil, err
		}
		if rn < mgmtHdrLen+3 {
			continue
		}
		evt := binary.LittleEndian.Uint16(buf[0:2])
		// idx := binary.LittleEndian.Uint16(buf[2:4])
		plen := binary.LittleEndian.Uint16(buf[4:6])
		if int(mgmtHdrLen+plen) > rn {
			continue
		}
		body := buf[mgmtHdrLen : mgmtHdrLen+plen]
		switch evt {
		case mgmtEvCmdComplete:
			if len(body) < 3 {
				continue
			}
			cmdOp := binary.LittleEndian.Uint16(body[0:2])
			status := body[2]
			if cmdOp != op {
				continue
			}
			if status != 0 {
				return nil, fmt.Errorf("MGMT op 0x%04x failed with status 0x%02x", op, status)
			}
			return append([]byte(nil), body[3:]...), nil
		case mgmtEvCmdStatus:
			if len(body) < 3 {
				continue
			}
			cmdOp := binary.LittleEndian.Uint16(body[0:2])
			status := body[2]
			if cmdOp == op && status != 0 {
				return nil, fmt.Errorf("MGMT op 0x%04x status 0x%02x", op, status)
			}
		}
	}
	return nil, fmt.Errorf("MGMT op 0x%04x: timeout waiting for Command Complete", op)
}

// SetAddress sends the vendor-specific write command for the named vendor and
// then waits briefly for any Command Complete event. The HCI_CHANNEL_RAW
// socket is opened per-call so we don't hold it open longer than needed.
func SetAddress(idx uint16, vendor string, addr [6]byte) error {
	cmd, ok := lookupVendor(vendor)
	if !ok {
		return fmt.Errorf("unknown vendor %q (try --list-vendors)", vendor)
	}
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, btprotoHCI)
	if err != nil {
		return fmt.Errorf("AF_BLUETOOTH socket: %w (sudo required)", err)
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrHCI{Dev: idx, Channel: hciChannelRaw}
	if err := unix.Bind(fd, sa); err != nil {
		return fmt.Errorf("bind hci%d raw: %w (sudo required)", idx, err)
	}

	payload, err := cmd.Build(addr)
	if err != nil {
		return err
	}
	// HCI command packet: type=0x01, opcode (LE), plen (1B), parameters.
	pkt := make([]byte, 4+len(payload))
	pkt[0] = hciCommandPkt
	binary.LittleEndian.PutUint16(pkt[1:3], cmd.Opcode)
	pkt[3] = byte(len(payload))
	copy(pkt[4:], payload)
	if _, err := unix.Write(fd, pkt); err != nil {
		return fmt.Errorf("write HCI command: %w", err)
	}

	// Best-effort drain: vendor commands often don't deliver completion to
	// userspace on modern kernels. Wait up to 500ms for anything inbound and
	// then move on.
	_ = unix.SetNonblock(fd, true)
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	buf := make([]byte, 1024)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, _ := unix.Poll(pfd, 100)
		if n == 0 {
			continue
		}
		if _, err := unix.Read(fd, buf); err != nil {
			break
		}
	}
	return nil
}

// ResetAdapter issues an HCIDEVRESET ioctl on hciN. This is the only way
// known to make bluetoothd re-read the BD_ADDR after a vendor-specific
// write that mutates the controller's volatile address state — a soft
// Adapter1.Powered=false → true cycle re-loads from OTP on Intel chips,
// undoing the spoof. The ioctl on its own can leave the controller in
// BR/EDR INQUIRY mode, which silently blocks LE advertisement reception
// on Intel chips; callers must follow with cyclePower() (defined in
// internal/cli/adapter.go) to clear that side-effect.
func ResetAdapter(idx uint16) error {
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, btprotoHCI)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	const HCIDEVRESET = 0x400448cb // _IOW('H', 203, int) — kernel <bluetooth/hci.h>
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(HCIDEVRESET), uintptr(idx)); e != 0 {
		return fmt.Errorf("HCIDEVRESET: %w", e)
	}
	return nil
}
