package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/godbus/dbus/v5"

	bdaddrPkg "goatttool/internal/bdaddr"
	"goatttool/internal/fuzz/engine"
	"goatttool/internal/fuzz/oracle"
	"goatttool/internal/l2cap"
)

// l2capHarness drives writes through a raw L2CAP/ATT socket alongside
// BlueZ's existing LE link (Layer B). Used when the user passes --raw,
// and required for Prepare/Execute Write opcodes (which BlueZ exposes
// only via its "reliable" abstraction, not as individually-mutable
// primitives).
//
// Liveness probing still rides on the BlueZ session — we read the
// liveness characteristic via D-Bus. Cheap, robust, and keeps the
// L2CAP socket dedicated to the mutated writes.
type l2capHarness struct {
	addr           string
	addrType       uint8
	targetHandle   uint16
	livenessHandle uint16
	resetCmd       string
	noLiveness     bool
	timeout        time.Duration

	conn *l2cap.Conn
	sess *session
	live string // resolved liveness object path
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

func (h *l2capHarness) connect() error {
	// L2CAP socket for writes.
	leAddr, err := bdaddrPkg.ParseMAC(h.addr)
	if err != nil {
		return err
	}
	var peer [6]byte
	for i := 0; i < 6; i++ {
		peer[i] = leAddr[5-i]
	}
	c, err := l2cap.Dial(peer, h.addrType)
	if err != nil {
		return fmt.Errorf("l2cap dial: %w", err)
	}
	h.conn = c

	// BlueZ session for liveness probes + handle resolution.
	if !h.noLiveness {
		ctx, cancel := ctxWithRootTimeout()
		defer cancel()
		s, err := openSession(ctx, h.addr, true)
		if err != nil {
			_ = h.conn.Close()
			h.conn = nil
			return fmt.Errorf("liveness session: %w", err)
		}
		h.sess = s
		obj, ok := s.tree.ByHandle[h.livenessHandle]
		if !ok {
			s.close()
			_ = h.conn.Close()
			h.conn, h.sess = nil, nil
			return fmt.Errorf("liveness handle 0x%04x not in tree", h.livenessHandle)
		}
		h.live = string(obj.Path)
	}
	return nil
}

func (h *l2capHarness) Write(ctx context.Context, op engine.Op, value []byte) engine.WriteResult {
	if h.conn == nil {
		return engine.WriteResult{Resp: oracle.Response{Disconnected: true}, Err: errors.New("l2cap socket closed")}
	}

	switch op {
	case engine.OpWriteReq:
		r, err := h.conn.WriteRequestEx(h.targetHandle, value, h.timeout)
		return wrapATTResp(r, err)

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
		return wrapATTResp(r, err)

	case engine.OpExecWrite:
		// Input encoding: first byte's LSB = flags (0 cancel / 1 commit).
		// If the input is empty, default to commit.
		flags := uint8(l2cap.ExecFlagCommit)
		if len(value) > 0 {
			flags = value[0] & 0x01
		}
		r, err := h.conn.ExecuteWrite(flags, h.timeout)
		return wrapATTResp(r, err)
	}
	return engine.WriteResult{Err: fmt.Errorf("l2cap harness: unsupported op %s", op)}
}

func (h *l2capHarness) Liveness(ctx context.Context) error {
	if h.noLiveness || h.sess == nil {
		return nil
	}
	_, err := h.sess.conn.Characteristic(dbusPath(h.live)).ReadValue(0)
	return err
}

func (h *l2capHarness) Reset(ctx context.Context) error {
	if h.resetCmd == "" {
		return errors.New("--target-reset not set; cannot recover from liveness loss")
	}
	logf("firing --target-reset hook: %s", h.resetCmd)
	cm := exec.CommandContext(ctx, "sh", "-c", h.resetCmd)
	cm.Stdout = os.Stderr
	cm.Stderr = os.Stderr
	if err := cm.Run(); err != nil {
		return fmt.Errorf("reset command exited: %w", err)
	}
	// Tear everything down and rebuild from scratch — the reset is
	// expected to have closed the LE link.
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
	if h.sess != nil {
		h.sess.close()
		h.sess = nil
	}
	if err := h.connect(); err != nil {
		return fmt.Errorf("reconnect after reset: %w", err)
	}
	statusf("L2CAP/BlueZ reconnected after reset")
	return nil
}

func (h *l2capHarness) Close() error {
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
	if h.sess != nil {
		h.sess.close()
		h.sess = nil
	}
	return nil
}

// wrapATTResp converts an l2cap.Response (+ transport err) into the
// engine's WriteResult. The whole point of the L2CAP path: an ATT Error
// Response is signal, not failure — err is reserved for socket-dead
// scenarios.
func wrapATTResp(r l2cap.Response, err error) engine.WriteResult {
	if err != nil {
		return engine.WriteResult{
			Resp: oracle.Response{Disconnected: looksLikeDisconnect(err), Timeout: looksLikeTimeout(err)},
			Err:  err,
		}
	}
	return engine.WriteResult{
		Resp: oracle.Response{
			Opcode:  r.Opcode,
			ErrCode: r.ErrCode,
			Length:  len(r.Body),
		},
	}
}

func looksLikeDisconnect(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, marker := range []string{"connection reset", "broken pipe", "no route", "transport endpoint is not connected"} {
		if containsFold(s, marker) {
			return true
		}
	}
	return false
}

func looksLikeTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return containsFold(s, "timeout") || containsFold(s, "deadline") || containsFold(s, "resource temporarily unavailable")
}

func containsFold(s, sub string) bool {
	return indexFold(s, sub) >= 0
}

// indexFold is strings.Contains-with-ToLower without pulling in strings
// here just for the import — strings is already imported elsewhere in
// the package via other files.
func indexFold(s, sub string) int {
	// cheap path: both lowercase
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// dbusPath is the type alias trampoline for godbus's ObjectPath.
// Pulling godbus into this file directly would create a circular-looking
// import (cli already pulls it transitively); instead we keep paths as
// strings here and convert at the boundary.
func dbusPath(s string) dbus.ObjectPath { return dbus.ObjectPath(s) }
