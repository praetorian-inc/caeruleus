package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	bdaddrPkg "goatttool/internal/bdaddr"
	"goatttool/internal/fuzz/engine"
	"goatttool/internal/fuzz/oracle"
	"goatttool/internal/l2cap"
)

// l2capHarness drives writes through a raw L2CAP/ATT socket and runs
// alone — no parallel BlueZ session. The earlier "BlueZ for liveness +
// L2CAP for writes" design fell over on the most interesting bug class:
// targets whose chars BlueZ claims for itself, where the kernel refuses
// a second L2CAP socket on CID 0x0004. We now disconnect BlueZ at start
// and drive everything (writes, liveness, reconnect) through the raw
// socket.
//
// Liveness is a Read Request to a known-good handle (default 0x0001,
// the GATT primary service declaration — universally present on
// standards-compliant BLE servers). Override with --liveness-handle.
type l2capHarness struct {
	addr           string
	addrType       uint8
	targetHandle   uint16
	livenessHandle uint16
	resetCmd       string
	noLiveness     bool
	timeout        time.Duration

	conn *l2cap.Conn
}

func newL2CAPHarness(addr string, target, liveness uint16, resetCmd string, noLiveness bool, timeout time.Duration) (*l2capHarness, error) {
	if err := requireRoot("fuzz write --raw"); err != nil {
		return nil, err
	}
	at := uint8(l2cap.BDADDRLEPublic)
	if root.addrType == "random" {
		at = l2cap.BDADDRLERandom
	}
	h := &l2capHarness{
		addr:           addr,
		addrType:       at,
		targetHandle:   target,
		livenessHandle: liveness,
		resetCmd:       resetCmd,
		noLiveness:     noLiveness,
		timeout:        timeout,
	}
	if err := h.connect(); err != nil {
		return nil, err
	}
	return h, nil
}

// connect detaches BlueZ from the peer if needed, then opens a fresh
// raw L2CAP socket. We do NOT keep a parallel BlueZ session — see the
// package comment for why.
func (h *l2capHarness) connect() error {
	leAddr, err := bdaddrPkg.ParseMAC(h.addr)
	if err != nil {
		return err
	}
	var peer [6]byte
	for i := 0; i < 6; i++ {
		peer[i] = leAddr[5-i]
	}

	// Try opening L2CAP directly first; if the kernel says EBUSY, BlueZ
	// is holding the link — detach via Device1.Disconnect() and retry.
	conn, err := l2cap.Dial(peer, h.addrType)
	if err != nil && isResourceBusy(err) {
		logf("L2CAP EBUSY — disconnecting BlueZ from %s and retrying", h.addr)
		if derr := detachBlueZ(h.addr); derr != nil {
			return fmt.Errorf("detach BlueZ: %w (original dial error: %v)", derr, err)
		}
		// Give the kernel a moment to release CID 0x0004.
		time.Sleep(300 * time.Millisecond)
		conn, err = l2cap.Dial(peer, h.addrType)
	}
	if err != nil {
		return fmt.Errorf("l2cap dial: %w", err)
	}
	h.conn = conn
	return nil
}

// detachBlueZ asks bluetoothd to drop the LE link to addr. Idempotent —
// if BlueZ doesn't know the device or it's already disconnected, this
// returns nil.
func detachBlueZ(addr string) error {
	// Minimal D-Bus dance. We can't reuse openSession because that
	// CONNECTS to the device; we want the opposite.
	ctx, cancel := ctxWithRootTimeout()
	defer cancel()
	s, err := openSession(ctx, "", false) // no device, just BlueZ conn
	if err != nil {
		return err
	}
	defer s.close()
	dev := s.conn.Device(addr)
	if connected, perr := dev.Connected(); perr == nil && !connected {
		return nil
	}
	if err := dev.Disconnect(); err != nil {
		// "unknown device" / "no such object" — BlueZ never saw it; fine.
		if strings.Contains(strings.ToLower(err.Error()), "no such") ||
			strings.Contains(strings.ToLower(err.Error()), "unknown") {
			return nil
		}
		return err
	}
	// Poll for Connected=false so the kernel actually releases the link
	// before we try L2CAP again.
	return pollUntil(ctx, func() bool {
		c, perr := dev.Connected()
		return perr != nil || !c
	}, 50*time.Millisecond, 2*time.Second)
}

func isResourceBusy(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "device or resource busy") || strings.Contains(s, "ebusy")
}

func (h *l2capHarness) Write(ctx context.Context, op engine.Op, value []byte) engine.WriteResult {
	if h.conn == nil {
		return engine.WriteResult{Resp: oracle.Response{Disconnected: true}, Err: errors.New("l2cap socket closed")}
	}

	switch op {
	case engine.OpWriteReq:
		r, err := h.conn.WriteRequestEx(h.targetHandle, value, h.timeout)
		return wrapATTResp(r, err, l2cap.OpWriteResponse)

	case engine.OpWriteCmd:
		if err := h.conn.WriteCommand(h.targetHandle, value); err != nil {
			return engine.WriteResult{
				Resp: oracle.Response{Disconnected: looksLikeDisconnect(err)},
				Err:  err,
			}
		}
		// No response from the peer for Write Command — opcode 0 in the
		// oracle tuple signals "we sent and got nothing back".
		return engine.WriteResult{Resp: oracle.Response{}}

	case engine.OpPrepWrite:
		// Input encoding: first 2 bytes = LE offset, rest = value chunk.
		// Empty/short inputs degrade to offset=0 / empty chunk.
		var offset uint16
		var chunk []byte
		switch {
		case len(value) >= 2:
			offset = binary.LittleEndian.Uint16(value[:2])
			chunk = value[2:]
		case len(value) == 1:
			offset = uint16(value[0])
		}
		r, err := h.conn.PrepareWrite(h.targetHandle, offset, chunk, h.timeout)
		return wrapATTResp(r, err, l2cap.OpPrepareWriteResponse)

	case engine.OpExecWrite:
		// Input encoding: first byte's LSB = flags (0 cancel / 1 commit).
		flags := uint8(l2cap.ExecFlagCommit)
		if len(value) > 0 {
			flags = value[0] & 0x01
		}
		r, err := h.conn.ExecuteWrite(flags, h.timeout)
		return wrapATTResp(r, err, l2cap.OpExecuteWriteResponse)
	}
	return engine.WriteResult{Err: fmt.Errorf("l2cap harness: unsupported op %s", op)}
}

func (h *l2capHarness) Liveness(ctx context.Context) error {
	if h.noLiveness || h.conn == nil {
		return nil
	}
	r, err := h.conn.ReadRequest(h.livenessHandle, h.timeout)
	if err != nil {
		return err
	}
	switch r.Opcode {
	case l2cap.OpReadResponse:
		return nil
	case l2cap.OpErrorResponse:
		// Read failures on a normally-readable handle are legitimately
		// a liveness signal too — but not if it's "Read Not Permitted"
		// on a write-only handle the user chose. Treat any non-disconnect
		// error response as alive-but-grumpy: live=true, we want to keep
		// fuzzing.
		return nil
	default:
		// Unexpected opcode (e.g., the 0x02 garbage we observed from a
		// crashing target). Treat as liveness failure — the link is
		// returning corrupt PDUs.
		return fmt.Errorf("liveness Read got unexpected opcode 0x%02x", r.Opcode)
	}
}

func (h *l2capHarness) Reset(ctx context.Context) error {
	// resetCmd is optional in L2CAP mode — if absent we just close the
	// socket, wait a bit (target reboot window), and reopen. The reset
	// hook adds an explicit shell step on top of that.
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
	if h.resetCmd != "" {
		logf("firing --target-reset hook: %s", h.resetCmd)
		cm := exec.CommandContext(ctx, "sh", "-c", h.resetCmd)
		cm.Stdout = os.Stderr
		cm.Stderr = os.Stderr
		if err := cm.Run(); err != nil {
			return fmt.Errorf("reset command exited: %w", err)
		}
	} else {
		// Default settle window — long enough for an nRF52 / similar
		// MCU to crash, watchdog-reset, re-advertise.
		time.Sleep(8 * time.Second)
	}
	if err := h.connect(); err != nil {
		return fmt.Errorf("reconnect after reset: %w", err)
	}
	statusf("L2CAP reconnected after reset")
	return nil
}

func (h *l2capHarness) Close() error {
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
	return nil
}

// wrapATTResp converts an l2cap.Response (+ transport err) into the
// engine's WriteResult. The whole point of the L2CAP path: an ATT Error
// Response is signal, not failure — err is reserved for socket-dead
// scenarios.
//
// expectedOK is the opcode the peer is supposed to return on success
// for the request we sent (e.g. 0x13 for Write Request). The peer may
// also legally return Error Response (0x01). Anything else — like the
// 0x02 garbage we've seen from crashing firmware — is treated as
// disconnect so the engine attributes the crash to *this* input, not
// the next one that finally trips the socket-dead error.
func wrapATTResp(r l2cap.Response, err error, expectedOK uint8) engine.WriteResult {
	if err != nil {
		return engine.WriteResult{
			Resp: oracle.Response{Disconnected: looksLikeDisconnect(err), Timeout: looksLikeTimeout(err)},
			Err:  err,
		}
	}
	resp := oracle.Response{
		Opcode:  r.Opcode,
		ErrCode: r.ErrCode,
		Length:  len(r.Body),
	}
	// Validate the opcode is one we'd expect. Error Response (0x01) is
	// always legal; the request-specific success opcode is too. Anything
	// else — including the empirically-observed 0x02 from buffer-overflow
	// firmware — is treated as a crash indicator on *this* iteration.
	if r.Opcode != expectedOK && r.Opcode != l2cap.OpErrorResponse {
		resp.Disconnected = true
	}
	return engine.WriteResult{Resp: resp}
}

func looksLikeDisconnect(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, marker := range []string{"connection reset", "broken pipe", "no route", "transport endpoint is not connected", "host is down"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func looksLikeTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "timeout") || strings.Contains(s, "deadline") || strings.Contains(s, "resource temporarily unavailable")
}
