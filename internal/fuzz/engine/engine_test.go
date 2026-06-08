package engine

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"caeruleus/internal/fuzz/corpus"
	"caeruleus/internal/fuzz/mutate"
	"caeruleus/internal/fuzz/oracle"
	"caeruleus/internal/fuzz/trace"
)

// fakeHarness lets us drive engine.Run with deterministic responses for
// unit tests. Field functions are nil-safe: zero values mean "always ok".
type fakeHarness struct {
	writes    int64
	liveness  int64
	resets    int64
	writeFn   func(op Op, value []byte) (oracle.Response, error)
	liveFn    func() error
	resetFn   func() error
}

func (f *fakeHarness) Write(ctx context.Context, op Op, value []byte) WriteResult {
	atomic.AddInt64(&f.writes, 1)
	if f.writeFn == nil {
		return WriteResult{Resp: oracle.Response{Opcode: 0x13}}
	}
	r, e := f.writeFn(op, value)
	return WriteResult{Resp: r, Err: e}
}
func (f *fakeHarness) Liveness(ctx context.Context) error {
	atomic.AddInt64(&f.liveness, 1)
	if f.liveFn == nil {
		return nil
	}
	return f.liveFn()
}
func (f *fakeHarness) Reset(ctx context.Context) error {
	atomic.AddInt64(&f.resets, 1)
	if f.resetFn == nil {
		return nil
	}
	return f.resetFn()
}
func (f *fakeHarness) Close() error { return nil }

func mkEngine(t *testing.T, cfg Config, h Harness) (*Engine, *corpus.Corpus) {
	t.Helper()
	dir := t.TempDir()
	c, err := corpus.New(dir)
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	tw, err := trace.New(filepath.Join(dir, "trace.jsonl"))
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	t.Cleanup(func() { _ = tw.Close() })
	return &Engine{
		H:       h,
		Mutator: mutate.New(1, 64),
		Corpus:  c,
		Oracle:  oracle.New(),
		Trace:   tw,
		Cfg:     cfg,
	}, c
}

func TestRun_BasicIterations(t *testing.T) {
	h := &fakeHarness{}
	cfg := Config{
		Ops:           []Op{OpWriteReq},
		MaxIter:       50,
		LivenessEvery: 0, // disable
		Seeds:         [][]byte{[]byte("hello")},
		RNGSeed:       42,
	}
	eng, _ := mkEngine(t, cfg, h)
	stats, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Iter != 50 {
		t.Errorf("expected 50 iterations, got %d", stats.Iter)
	}
	if atomic.LoadInt64(&h.writes) != 50 {
		t.Errorf("expected 50 Write calls, got %d", h.writes)
	}
	if stats.States == 0 {
		t.Errorf("expected at least one state in oracle, got 0")
	}
}

func TestRun_DisconnectClassifiesCrash(t *testing.T) {
	h := &fakeHarness{
		writeFn: func(op Op, value []byte) (oracle.Response, error) {
			// Disconnect on the 5th write, normal otherwise.
			return oracle.Response{Disconnected: false, Opcode: 0x13}, nil
		},
	}
	disconnectOn := 5
	count := 0
	h.writeFn = func(op Op, value []byte) (oracle.Response, error) {
		count++
		if count == disconnectOn {
			return oracle.Response{Disconnected: true}, nil
		}
		return oracle.Response{Opcode: 0x13}, nil
	}
	cfg := Config{
		Ops:           []Op{OpWriteReq},
		MaxIter:       20,
		LivenessEvery: 0,
		Seeds:         [][]byte{[]byte("x")},
		RNGSeed:       1,
	}
	eng, _ := mkEngine(t, cfg, h)
	stats, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Crashes != 1 {
		t.Errorf("expected 1 crash, got %d", stats.Crashes)
	}
}

func TestRun_LivenessFailureFiresReset(t *testing.T) {
	calls := 0
	h := &fakeHarness{
		liveFn: func() error {
			calls++
			if calls <= 3 {
				return errors.New("dead")
			}
			return nil
		},
	}
	cfg := Config{
		Ops:           []Op{OpWriteReq},
		MaxIter:       30,
		LivenessEvery: 1,
		ResetAfter:    3,
		Seeds:         [][]byte{[]byte("x")},
		RNGSeed:       1,
	}
	eng, _ := mkEngine(t, cfg, h)
	if _, err := eng.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if h.resets != 1 {
		t.Errorf("expected reset hook to fire exactly once, got %d", h.resets)
	}
}

func TestRun_ResetFailureAborts(t *testing.T) {
	h := &fakeHarness{
		liveFn:  func() error { return errors.New("dead forever") },
		resetFn: func() error { return errors.New("plug script missing") },
	}
	cfg := Config{
		Ops:           []Op{OpWriteReq},
		MaxIter:       50,
		LivenessEvery: 1,
		ResetAfter:    2,
		Seeds:         [][]byte{[]byte("x")},
		RNGSeed:       1,
	}
	eng, _ := mkEngine(t, cfg, h)
	stats, err := eng.Run(context.Background())
	if err == nil {
		t.Fatalf("expected reset-failure error, got nil")
	}
	if stats.Iter > 5 {
		t.Errorf("expected early abort, ran %d iter", stats.Iter)
	}
}

func TestRun_ContextCancel(t *testing.T) {
	h := &fakeHarness{
		writeFn: func(op Op, value []byte) (oracle.Response, error) {
			time.Sleep(5 * time.Millisecond)
			return oracle.Response{Opcode: 0x13}, nil
		},
	}
	cfg := Config{
		Ops:           []Op{OpWriteReq},
		MaxIter:       10000,
		LivenessEvery: 0,
		Seeds:         [][]byte{[]byte("x")},
		RNGSeed:       1,
	}
	eng, _ := mkEngine(t, cfg, h)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	stats, err := eng.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Iter == 10000 {
		t.Errorf("expected early exit on ctx cancel, ran to MaxIter")
	}
}
