// Package engine is the fuzzing main loop: pick a parent input, mutate
// it, hand it to the transport-specific Harness, classify the response,
// log, and decide on corpus admission. The engine is transport-agnostic
// — Phase 1a wires a BlueZ-D-Bus Harness, Phase 1b a raw-L2CAP Harness.
package engine

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"goatttool/internal/fuzz/corpus"
	"goatttool/internal/fuzz/mutate"
	"goatttool/internal/fuzz/oracle"
	"goatttool/internal/fuzz/trace"
)

// Op is the ATT write variant the engine will exercise. The Harness is
// expected to map this to the appropriate transport-layer call.
type Op uint8

const (
	OpWriteReq   Op = iota // 0x12 — Write Request, has Write Response
	OpWriteCmd             // 0x52 — Write Command, no response
	OpPrepWrite            // 0x16 — Prepare Write Request, multi-PDU prefix
	OpExecWrite            // 0x18 — Execute Write Request, finalizer
)

// String returns the short opcode name used in trace records.
func (o Op) String() string {
	switch o {
	case OpWriteReq:
		return "write_req"
	case OpWriteCmd:
		return "write_cmd"
	case OpPrepWrite:
		return "prep_write"
	case OpExecWrite:
		return "exec_write"
	default:
		return fmt.Sprintf("op_%d", o)
	}
}

// ParseOp turns a CLI string into an Op. Returns ok=false on unknown.
func ParseOp(s string) (Op, bool) {
	switch s {
	case "req", "write_req", "write-req":
		return OpWriteReq, true
	case "cmd", "write_cmd", "write-cmd":
		return OpWriteCmd, true
	case "prep", "prep_write", "prepare":
		return OpPrepWrite, true
	case "exec", "exec_write", "execute":
		return OpExecWrite, true
	}
	return 0, false
}

// WriteResult is what the Harness returns from a single Write call. Err
// is reserved for transport-level problems (socket dead, D-Bus call
// failed) that aren't about the peer's ATT response; ATT Error
// Responses are conveyed via Resp.Opcode == 0x01 + Resp.ErrCode.
type WriteResult struct {
	Resp oracle.Response
	Err  error
}

// Harness adapts a transport (BlueZ D-Bus, raw L2CAP, future HCI) to the
// engine. Implementations live in cli/fuzz_*.go alongside the
// subcommand that wires them up.
type Harness interface {
	Write(ctx context.Context, op Op, value []byte) WriteResult
	Liveness(ctx context.Context) error
	Reset(ctx context.Context) error
	Close() error
}

// Config holds engine settings. Most fields have sensible zero defaults
// once Defaults() has been applied.
type Config struct {
	Ops             []Op
	MaxIter         int
	MaxTime         time.Duration
	LivenessEvery   int
	ResetAfter      int
	RNGSeed         int64
	MaxValueLen     int      // hard cap on input length (typically MTU-3)
	Seeds           [][]byte // initial parent pool; if empty, one empty seed is used
	NoStateFeedback bool
	Quiet           bool
	StatusEvery     int                          // emit a Status() callback every N iter; 0 disables
	Status          func(string, ...interface{}) // printf-style; engine adds no prefix
}

// Defaults applies sane fallbacks to unset Config fields. Called by Run
// so callers don't have to.
func (c *Config) Defaults() {
	if c.MaxIter <= 0 {
		c.MaxIter = 10000
	}
	if c.LivenessEvery <= 0 {
		c.LivenessEvery = 10
	}
	if c.ResetAfter <= 0 {
		c.ResetAfter = 3
	}
	if c.StatusEvery <= 0 {
		c.StatusEvery = 100
	}
	if c.Status == nil {
		c.Status = func(string, ...interface{}) {}
	}
	if len(c.Ops) == 0 {
		c.Ops = []Op{OpWriteReq}
	}
}

// Engine is the assembled fuzzing run. Build via New, then call Run.
type Engine struct {
	H       Harness
	Mutator *mutate.Mutator
	Corpus  *corpus.Corpus
	Oracle  *oracle.Oracle
	Trace   *trace.Writer
	Cfg     Config
}

// Stats summarizes a completed run; also returned on error/abort.
type Stats struct {
	Iter     int
	Crashes  int
	Hangs    int
	Queue    int
	States   int
	Duration time.Duration
}

// Run executes the main loop until MaxIter, MaxTime, ctx cancellation,
// or a fatal Reset failure. Errors from individual iterations are logged
// to the trace and don't abort the run; only Reset failure does.
func (e *Engine) Run(ctx context.Context) (Stats, error) {
	e.Cfg.Defaults()
	stats := Stats{}

	parentPool := make([][]byte, 0, len(e.Cfg.Seeds)+1)
	parentPool = append(parentPool, e.Cfg.Seeds...)
	if len(parentPool) == 0 {
		parentPool = append(parentPool, []byte{})
	}
	for _, s := range parentPool {
		if _, err := e.Corpus.Add(corpus.CatCorpus, s, nil); err != nil {
			return stats, fmt.Errorf("seed corpus: %w", err)
		}
	}

	rng := rand.New(rand.NewSource(e.Cfg.RNGSeed))
	var deadline time.Time
	if e.Cfg.MaxTime > 0 {
		deadline = time.Now().Add(e.Cfg.MaxTime)
	}

	start := time.Now()
	consecLive := 0

	for iter := 0; iter < e.Cfg.MaxIter; iter++ {
		if err := ctx.Err(); err != nil {
			break
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}

		parent := parentPool[rng.Intn(len(parentPool))]
		op := e.Cfg.Ops[rng.Intn(len(e.Cfg.Ops))]
		input := e.Mutator.Mutate(parent, parentPool)
		if e.Cfg.MaxValueLen > 0 && len(input) > e.Cfg.MaxValueLen {
			input = input[:e.Cfg.MaxValueLen]
		}

		t0 := time.Now()
		result := e.H.Write(ctx, op, input)
		elapsed := time.Since(t0)

		liveOK := true
		liveProbed := false
		if e.Cfg.LivenessEvery > 0 && (iter%e.Cfg.LivenessEvery == 0 || result.Resp.Disconnected || result.Resp.Timeout) {
			liveProbed = true
			if err := e.H.Liveness(ctx); err != nil {
				liveOK = false
			}
		}

		verdict := oracle.Verdict{Crash: result.Resp.Disconnected, Hang: !liveOK}
		if !e.Cfg.NoStateFeedback {
			verdict = e.Oracle.Classify(byte(op), result.Resp, liveOK)
		}

		rec := trace.Record{
			Iter:     iter,
			Mut:      e.Mutator.Last,
			ParentID: corpus.ID(parent),
			InputID:  corpus.ID(input),
			Input:    trace.HexInput(input),
			Op:       op.String(),
			Live:     liveOK,
			NewState: verdict.NewState,
			Crash:    verdict.Crash,
			Hang:     verdict.Hang,
			MS:       elapsed.Milliseconds(),
		}
		fillRespFields(&rec, result.Resp)
		if result.Err != nil {
			rec.Err = result.Err.Error()
		}
		_ = e.Trace.Write(rec)

		if verdict.NewState && !e.Cfg.NoStateFeedback {
			if _, err := e.Corpus.Add(corpus.CatQueue, input, rec); err == nil {
				parentPool = append(parentPool, input)
				stats.Queue++
			}
		}
		if verdict.Crash {
			_, _ = e.Corpus.Add(corpus.CatCrashes, input, rec)
			stats.Crashes++
		}

		switch {
		case verdict.Hang:
			consecLive++
			if consecLive >= e.Cfg.ResetAfter {
				_, _ = e.Corpus.Add(corpus.CatHangs, input, rec)
				stats.Hangs++
				if err := e.H.Reset(ctx); err != nil {
					stats.Iter = iter + 1
					stats.States = e.Oracle.States()
					stats.Duration = time.Since(start)
					return stats, fmt.Errorf("reset failed after %d consecutive liveness failures: %w",
						consecLive, err)
				}
				consecLive = 0
			}
		case liveProbed:
			consecLive = 0
		}

		if e.Cfg.StatusEvery > 0 && (iter+1)%e.Cfg.StatusEvery == 0 {
			e.Cfg.Status("iter=%d states=%d queue=%d crashes=%d hangs=%d elapsed=%s",
				iter+1, e.Oracle.States(), stats.Queue, stats.Crashes, stats.Hangs,
				time.Since(start).Round(time.Second))
		}

		stats.Iter = iter + 1
	}

	stats.States = e.Oracle.States()
	stats.Duration = time.Since(start)
	return stats, nil
}

func fillRespFields(rec *trace.Record, r oracle.Response) {
	switch {
	case r.Disconnected:
		rec.RespOp = "disconnect"
	case r.Timeout:
		rec.RespOp = "timeout"
	case r.Opcode != 0:
		rec.RespOp = fmt.Sprintf("0x%02x", r.Opcode)
		if r.Opcode == 0x01 {
			rec.ErrCode = fmt.Sprintf("0x%02x", r.ErrCode)
		}
		rec.RespLen = r.Length
	}
}

// ErrNoOps is returned if Config.Ops would be empty after Defaults — a
// guard for misconfigured callers.
var ErrNoOps = errors.New("engine: no Ops configured")
