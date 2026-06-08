// Package oracle classifies fuzzer iterations using an AFLNet-style
// response-tuple state hash. We can't instrument a blackbox BLE
// peripheral, so we approximate coverage by treating distinct response
// shapes as distinct states; an input that reaches a previously-unseen
// state is admitted to the queue for further mutation.
//
// The tuple is (write_opcode, response_opcode, error_code, length_bucket).
// Length is bucketed so e.g. "20 bytes back" and "23 bytes back" don't
// blow up the state set.
package oracle

import (
	"sync"
)

// Response is the minimum information the engine extracts from a single
// write-then-read cycle. Disconnected/Timeout are independent — a
// timeout in the absence of disconnect typically signals app-layer hang.
type Response struct {
	Disconnected bool
	Timeout      bool
	Opcode       uint8 // ATT opcode of the response PDU; 0 if none came back
	ErrCode      uint8 // ATT error code if Opcode == 0x01; 0 otherwise
	Length       int   // number of bytes in the response PDU body (post-opcode)
}

// Verdict is the oracle's per-iteration judgement.
type Verdict struct {
	NewState bool
	Crash    bool
	Hang     bool
}

// Oracle tracks the set of seen response tuples across a run.
type Oracle struct {
	mu     sync.Mutex
	states map[uint64]struct{}
}

// New returns an empty oracle.
func New() *Oracle {
	return &Oracle{states: make(map[uint64]struct{})}
}

// Classify reports whether (writeOp, resp) is a new state, whether it
// indicates a crash (disconnect or controller fatal), and whether the
// caller's separately-measured liveness probe failed (Hang).
//
// liveness=true means the probe succeeded (or was skipped); false means
// it failed for this iteration and the caller should consider whether
// to escalate to the reset hook.
func (o *Oracle) Classify(writeOp uint8, resp Response, liveness bool) Verdict {
	o.mu.Lock()
	defer o.mu.Unlock()

	key := stateKey(writeOp, resp)
	_, seen := o.states[key]
	if !seen {
		o.states[key] = struct{}{}
	}

	return Verdict{
		NewState: !seen,
		Crash:    resp.Disconnected,
		Hang:     !liveness,
	}
}

// States returns the count of distinct tuples seen.
func (o *Oracle) States() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.states)
}

// stateKey collapses (writeOp, respOp, errCode, lenBucket) into a uint64.
// Layout: byte0 = writeOp, byte1 = respOp, byte2 = errCode, byte3 = lenBucket.
func stateKey(writeOp uint8, r Response) uint64 {
	return uint64(writeOp) |
		uint64(r.Opcode)<<8 |
		uint64(r.ErrCode)<<16 |
		uint64(lengthBucket(r.Length))<<24
}

// lengthBucket maps a response length to a small bucket index. The exact
// bucket boundaries are tuned to ATT — BLE PDUs are 0-251 bytes; common
// shapes (empty Write Response, 5-byte Error Response, 23-byte default
// MTU read) get their own bucket.
func lengthBucket(n int) uint8 {
	switch {
	case n <= 0:
		return 0
	case n <= 1:
		return 1
	case n <= 4:
		return 2
	case n <= 16:
		return 3
	case n <= 64:
		return 4
	case n <= 251:
		return 5
	default:
		return 6
	}
}
