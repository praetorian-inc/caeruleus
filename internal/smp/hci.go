package smp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Raw HCI user-channel transport. Opening it takes exclusive control of the
// controller (the kernel host stack is bypassed), so bluetoothd must not be
// managing the adapter while this is active - the controller is brought down
// first. Requires root (CAP_NET_ADMIN + CAP_NET_RAW).

const (
	btprotoHCI     = 1
	hciChannelUser = 1 // HCI_CHANNEL_USER

	// HCIDEV* ioctls (_IOW('H', n, int)); take the device index as the arg.
	hciDevUp   = 0x400448c9
	hciDevDown = 0x400448ca

	// HCI packet indicators (first byte on the user channel).
	pktCommand = 0x01
	pktACL     = 0x02
	pktEvent   = 0x04

	// HCI event codes.
	evtDisconnComplete = 0x05
	evtCmdComplete     = 0x0e
	evtCmdStatus       = 0x0f
	evtLEMeta          = 0x3e
	leConnComplete     = 0x01

	// HCI command opcodes (OGF<<10 | OCF).
	cmdReset              = 0x0c03
	cmdSetEventMask       = 0x0c01
	cmdDisconnect         = 0x0406
	cmdLESetEventMask     = 0x2001
	cmdLECreateConn       = 0x200d
	cmdLECreateConnCancel = 0x200e

	cidSMP = 0x0006 // L2CAP fixed channel for the Security Manager
)

var (
	errTimeout  = errors.New("hci: read timeout")
	errTryAgain = errors.New("hci: try again")
)

// Dev is an open HCI user channel with at most one active LE connection.
type Dev struct {
	fd           int
	index        uint16
	connHandle   uint16
	stoppedBluez bool // we stopped bluetoothd in Open; Close restarts it
}

// bluezActive reports whether the bluetooth systemd service is running.
func bluezActive() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "bluetooth").Run() == nil
}

// systemctlBluez runs `systemctl <action> bluetooth` (action = start|stop).
func systemctlBluez(action string) error {
	return exec.Command("systemctl", action, "bluetooth").Run()
}

// IsUARTTransport reports whether the HCI controller at the given index is
// attached via a UART serial transport (e.g. Raspberry Pi onboard BT). Raw
// (HCI_CHANNEL_USER) ops still work on such controllers — Open manages
// bluetoothd and the controller recovers via HCIDEVUP — so this is used only
// for a doctor advisory, not to refuse the operation.
func IsUARTTransport(index uint16) bool {
	// Resolve the controller's sysfs device path and classify by transport.
	// USB/PCI dongles resolve under a path containing "/usb" or "/pci".
	// UART/serdev-attached controllers (e.g. Raspberry Pi onboard BCM43xx
	// over ttyAMA0) resolve under a serial/tty node, e.g.
	// /sys/devices/platform/soc/fe201000.serial/tty/ttyAMA0/hci0, and have
	// no device/modalias or type file at all — which is exactly why the old
	// modalias/type checks missed them and defaulted to "not UART".
	base := fmt.Sprintf("/sys/class/bluetooth/hci%d", index)
	if real, err := filepath.EvalSymlinks(base); err == nil {
		low := strings.ToLower(real)
		switch {
		case strings.Contains(low, "/usb"), strings.Contains(low, "/pci"):
			return false
		case strings.Contains(low, ".serial"), strings.Contains(low, "/tty"), strings.Contains(low, "/serial"):
			return true
		}
	}
	// Fallback: modalias (USB/PCI dongles expose usb:/pci:; serdev usually
	// has none). A non usb:/pci: modalias implies a platform/UART controller.
	if data, err := os.ReadFile(base + "/device/modalias"); err == nil {
		m := strings.TrimSpace(string(data))
		return !strings.HasPrefix(m, "usb:") && !strings.HasPrefix(m, "pci:")
	}
	// Path didn't clearly indicate USB/PCI and there's no modalias: assume
	// not UART, to avoid false positives that would block USB dongles.
	return false
}

// Open takes over the HCI controller `index` (e.g. 0 for hci0) via the user
// channel. bluetoothd must not hold the controller while the user channel is
// open, so Open stops bluetoothd for the duration and Close restarts it (only
// if Open stopped it).
//
// This works on UART-attached controllers (e.g. Raspberry Pi onboard BT) too:
// the controller recovers via HCIDEVUP on Close. The one thing that DOES wedge
// a UART controller is re-running btattach/hciattach (hciuart.service) while it
// is attached — caeruleus never does that.
func Open(index uint16) (_ *Dev, err error) {
	// HCI_CHANNEL_USER needs exclusive control, so bluetoothd must not hold the
	// controller. Stop bluetoothd for the duration (Close restarts it if we
	// stopped it). This is also what makes raw ops work on UART-attached
	// controllers (e.g. Raspberry Pi onboard BT): the controller recovers via
	// HCIDEVUP as long as bluetoothd isn't fighting and btattach/hciattach is
	// NOT re-run (re-running it is what actually wedges the UART transport).
	var stoppedBluez bool
	if bluezActive() {
		if e := systemctlBluez("stop"); e != nil {
			return nil, fmt.Errorf("stop bluetoothd for exclusive HCI access on hci%d: %w (needs root)", index, e)
		}
		stoppedBluez = true
		time.Sleep(300 * time.Millisecond) // let bluetoothd release the adapter
	}
	// Restore bluetoothd if we fail before handing ownership to a *Dev.
	defer func() {
		if err != nil && stoppedBluez {
			_ = systemctlBluez("start")
		}
	}()

	// Bring the controller down so the user channel can bind exclusively.
	if ctrl, e := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, btprotoHCI); e == nil {
		_ = unix.IoctlSetInt(ctrl, hciDevDown, int(index))
		unix.Close(ctrl)
	}
	fd, e := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, btprotoHCI)
	if e != nil {
		if errors.Is(e, unix.EPERM) || errors.Is(e, unix.EACCES) {
			return nil, fmt.Errorf("AF_BLUETOOTH socket: %w (run with sudo)", e)
		}
		return nil, fmt.Errorf("AF_BLUETOOTH socket: %w", e)
	}
	sa := &unix.SockaddrHCI{Dev: index, Channel: hciChannelUser}
	if e := unix.Bind(fd, sa); e != nil {
		unix.Close(fd)
		bringUp(index) // we downed it above; restore so the adapter isn't stranded
		return nil, fmt.Errorf("bind HCI user channel on hci%d: %w", index, e)
	}
	d := &Dev{fd: fd, index: index, connHandle: 0xffff, stoppedBluez: stoppedBluez}
	stoppedBluez = false // ownership transferred to d; d.Close restarts bluetoothd
	if e := d.reset(); e != nil {
		d.Close()
		return nil, e
	}
	return d, nil
}

// bringUp issues HCIDEVUP for the index on a throwaway control socket.
func bringUp(index uint16) {
	if ctrl, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, btprotoHCI); err == nil {
		_ = unix.IoctlSetInt(ctrl, hciDevUp, int(index))
		unix.Close(ctrl)
	}
}

// Close releases the controller and brings it back up so bluetoothd can
// reclaim it.
func (d *Dev) Close() error {
	if d.connHandle != 0xffff {
		_ = d.Disconnect()
	}
	err := unix.Close(d.fd)
	bringUp(d.index) // restore so bluetoothd can reclaim the adapter
	if d.stoppedBluez {
		_ = systemctlBluez("start") // restart the bluetoothd we stopped in Open
		d.stoppedBluez = false
	}
	return err
}

func (d *Dev) sendCmd(opcode uint16, params []byte) error {
	buf := make([]byte, 4+len(params))
	buf[0] = pktCommand
	binary.LittleEndian.PutUint16(buf[1:3], opcode)
	buf[3] = byte(len(params))
	copy(buf[4:], params)
	_, err := unix.Write(d.fd, buf)
	return err
}

// readPacket returns the next HCI packet (indicator byte stripped) or an error
// (errTimeout / errTryAgain are retryable).
func (d *Dev) readPacket(timeout time.Duration) (byte, []byte, error) {
	pfd := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
	ms := int(timeout / time.Millisecond)
	if ms <= 0 {
		ms = 1
	}
	n, err := unix.Poll(pfd, ms)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return 0, nil, errTryAgain
		}
		return 0, nil, err
	}
	if n == 0 {
		return 0, nil, errTimeout
	}
	buf := make([]byte, 4096)
	rn, err := unix.Read(d.fd, buf)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return 0, nil, errTryAgain
		}
		return 0, nil, err
	}
	if rn < 1 {
		return 0, nil, errTryAgain
	}
	return buf[0], append([]byte(nil), buf[1:rn]...), nil
}

// reset issues HCI Reset, then enables event delivery (the post-reset default
// event mask omits the LE Meta event, so LE Connection Complete would never
// reach the host).
func (d *Dev) reset() error {
	if err := d.sendCmd(cmdReset, nil); err != nil {
		return fmt.Errorf("HCI Reset: %w", err)
	}
	if err := d.waitCmdComplete(cmdReset, 2*time.Second); err != nil {
		return err
	}
	// Enable all events including the LE Meta event (bit 61).
	mask := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f}
	if err := d.sendCmd(cmdSetEventMask, mask); err != nil {
		return err
	}
	return d.waitCmdComplete(cmdSetEventMask, 2*time.Second)
}

// waitCmdComplete drains events until a Command Complete (or Command Status)
// for opcode arrives, checking the status byte.
func (d *Dev) waitCmdComplete(opcode uint16, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		typ, data, err := d.readPacket(time.Until(deadline))
		if err == errTimeout || err == errTryAgain {
			continue
		}
		if err != nil {
			return err
		}
		if typ != pktEvent || len(data) < 2 {
			continue
		}
		switch data[0] {
		case evtCmdComplete:
			// [code][plen][num_hci_cmd][opcode LE16][status...]
			if len(data) >= 6 && binary.LittleEndian.Uint16(data[3:5]) == opcode {
				if data[5] != 0 {
					return fmt.Errorf("command 0x%04x failed: HCI status 0x%02x", opcode, data[5])
				}
				return nil
			}
		case evtCmdStatus:
			// [code][plen][status][num_hci_cmd][opcode LE16]
			if len(data) >= 6 && binary.LittleEndian.Uint16(data[4:6]) == opcode {
				if data[2] != 0 {
					return fmt.Errorf("command 0x%04x status 0x%02x", opcode, data[2])
				}
				return nil
			}
		}
	}
	return fmt.Errorf("command 0x%04x: no completion within %s", opcode, timeout)
}

// Connect opens an LE connection to addr (MSB-first "AA:BB:..") of the given
// address type ("public" or "random") and returns once the LE Connection
// Complete event reports success.
func (d *Dev) Connect(addr, addrType string, timeout time.Duration) error {
	peer, err := parseAddrLE(addr)
	if err != nil {
		return err
	}
	var peerType byte = 0x00 // public
	if strings.EqualFold(addrType, "random") {
		peerType = 0x01
	}

	// Enable the LE Connection Complete meta event.
	mask := make([]byte, 8)
	mask[0] = 0x01 // bit0 = LE Connection Complete
	if err := d.sendCmd(cmdLESetEventMask, mask); err != nil {
		return err
	}
	if err := d.waitCmdComplete(cmdLESetEventMask, 2*time.Second); err != nil {
		return err
	}

	// LE Create Connection (Vol 4 Part E 7.8.12).
	p := make([]byte, 25)
	binary.LittleEndian.PutUint16(p[0:2], 0x0060)   // scan interval (60ms)
	binary.LittleEndian.PutUint16(p[2:4], 0x0030)   // scan window (30ms)
	p[4] = 0x00                                     // filter policy: use peer addr
	p[5] = peerType                                 // peer addr type
	copy(p[6:12], peer[:])                          // peer addr (LE)
	p[12] = 0x00                                    // own addr type: public
	binary.LittleEndian.PutUint16(p[13:15], 0x0018) // conn interval min (30ms)
	binary.LittleEndian.PutUint16(p[15:17], 0x0028) // conn interval max (50ms)
	binary.LittleEndian.PutUint16(p[17:19], 0x0000) // latency
	binary.LittleEndian.PutUint16(p[19:21], 0x012c) // supervision timeout (3s)
	binary.LittleEndian.PutUint16(p[21:23], 0x0000) // min CE length
	binary.LittleEndian.PutUint16(p[23:25], 0x0000) // max CE length
	if err := d.sendCmd(cmdLECreateConn, p); err != nil {
		return err
	}
	// Create Connection yields Command Status, then the LE Connection Complete
	// meta event carries the handle.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		typ, data, err := d.readPacket(time.Until(deadline))
		if err == errTimeout || err == errTryAgain {
			continue
		}
		if err != nil {
			return err
		}
		if typ != pktEvent || len(data) < 2 {
			continue
		}
		// Surface a rejected LE Create Connection (Command Status) instead of
		// silently waiting for a Connection Complete that will never come.
		if data[0] == evtCmdStatus && len(data) >= 6 &&
			binary.LittleEndian.Uint16(data[4:6]) == cmdLECreateConn && data[2] != 0 {
			return fmt.Errorf("LE Create Connection rejected: HCI status 0x%02x", data[2])
		}
		if data[0] != evtLEMeta {
			continue
		}
		params := data[2:]
		if len(params) < 1 || params[0] != leConnComplete || len(params) < 19 {
			continue
		}
		if params[1] != 0 {
			return fmt.Errorf("LE connect failed: HCI status 0x%02x", params[1])
		}
		d.connHandle = binary.LittleEndian.Uint16(params[2:4]) & 0x0fff
		return nil
	}
	_ = d.sendCmd(cmdLECreateConnCancel, nil)
	return fmt.Errorf("LE connect to %s: no Connection Complete within %s", addr, timeout)
}

// Disconnect tears down the active LE connection.
func (d *Dev) Disconnect() error {
	if d.connHandle == 0xffff {
		return nil
	}
	p := make([]byte, 3)
	binary.LittleEndian.PutUint16(p[0:2], d.connHandle)
	p[2] = 0x13 // remote user terminated
	err := d.sendCmd(cmdDisconnect, p)
	d.connHandle = 0xffff
	return err
}

// WriteSMP sends an SMP PDU over the L2CAP SMP fixed channel (CID 0x0006).
func (d *Dev) WriteSMP(pdu []byte) error {
	if d.connHandle == 0xffff {
		return errors.New("not connected")
	}
	// L2CAP B-frame: length(2) + CID(2) + payload.
	l2 := make([]byte, 4+len(pdu))
	binary.LittleEndian.PutUint16(l2[0:2], uint16(len(pdu)))
	binary.LittleEndian.PutUint16(l2[2:4], cidSMP)
	copy(l2[4:], pdu)
	// HCI ACL: indicator + handle|PB|BC(2) + data length(2) + L2CAP.
	acl := make([]byte, 5+len(l2))
	acl[0] = pktACL
	binary.LittleEndian.PutUint16(acl[1:3], d.connHandle&0x0fff) // PB=00 (LE start), BC=00
	binary.LittleEndian.PutUint16(acl[3:5], uint16(len(l2)))
	copy(acl[5:], l2)
	_, err := unix.Write(d.fd, acl)
	return err
}

// ReadSMP waits for and returns the next SMP PDU (L2CAP payload on CID 0x0006).
// A Disconnection Complete event returns an error so callers stop waiting.
func (d *Dev) ReadSMP(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		typ, data, err := d.readPacket(time.Until(deadline))
		if err == errTimeout || err == errTryAgain {
			continue
		}
		if err != nil {
			return nil, err
		}
		switch typ {
		case pktEvent:
			if len(data) >= 1 && data[0] == evtDisconnComplete {
				d.connHandle = 0xffff
				return nil, errors.New("peer disconnected")
			}
		case pktACL:
			if len(data) < 8 {
				continue
			}
			// data: handle+flags(2) + aclLen(2) + L2CAP[ len(2) + cid(2) + payload ]
			cid := binary.LittleEndian.Uint16(data[6:8])
			if cid != cidSMP {
				continue
			}
			// data: handle+flags(2) aclLen(2) | L2CAP: len(2) cid(2) payload
			// The SMP payload starts at offset 8 and is l2len bytes long.
			l2len := int(binary.LittleEndian.Uint16(data[4:6]))
			if 8+l2len > len(data) {
				l2len = len(data) - 8
			}
			return append([]byte(nil), data[8:8+l2len]...), nil
		}
	}
	return nil, errTimeout
}

// parseAddrLE converts "AA:BB:CC:DD:EE:FF" (MSB-first) into the little-endian
// 6-byte order the HCI wire format expects.
func parseAddrLE(addr string) ([6]byte, error) {
	var out [6]byte
	parts := strings.Split(strings.TrimSpace(addr), ":")
	if len(parts) != 6 {
		return out, fmt.Errorf("invalid BD_ADDR %q", addr)
	}
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return out, fmt.Errorf("invalid BD_ADDR %q", addr)
		}
		out[5-i] = byte(v) // reverse to little-endian
	}
	return out, nil
}
