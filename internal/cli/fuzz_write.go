package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/spf13/cobra"

	"goatttool/internal/bluez"
	"goatttool/internal/fuzz/corpus"
	"goatttool/internal/fuzz/engine"
	"goatttool/internal/fuzz/mutate"
	"goatttool/internal/fuzz/oracle"
	"goatttool/internal/fuzz/trace"
)

var fuzzWriteFlags struct {
	handle           string
	uuid             string
	seedFile         string
	seedDir          string
	seedASCII        string
	noSeed           bool
	rngSeed          int64
	maxIter          int
	maxTime          time.Duration
	maxValueLen      int
	types            string
	livenessHandle   string
	livenessEvery    int
	noLiveness       bool
	targetReset      string
	targetResetAfter int
	outDir           string
	noStateFeedback  bool
}

func newFuzzWriteCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "write",
		Short: "Fuzz writes to a single characteristic (Phase 1a: write_req, write_cmd)",
		Long: `Fuzz a single GATT characteristic by mutating writes. The default seed
is the current value of the target characteristic (auto-read at startup);
override with --seed-file / --seed / --seed-dir.

Each iteration:
  1. Pick a parent input from the corpus pool
  2. Apply 1+ mutations (bitflip / arith / interesting-values / splice / ...)
  3. Send the result via the chosen write variant
  4. Classify the response (or lack of it)
  5. Optionally probe a known-good handle for target liveness
  6. Admit to queue/ if the response tuple is new
  7. Admit to crashes/ if the target disconnected; hangs/ if the reset
     hook had to fire and didn't fully recover

Output (default ./fuzz-out-<ISO>/) is AFL-style: one file per input under
corpus/ queue/ crashes/ hangs/, plus run.json + trace.jsonl.

Phase 1a covers write_req and write_cmd. Prepare/Execute writes (and
the raw-L2CAP path) ship in Phase 1b — see docs/fuzzing-plan.md.

Examples:

  # Default: write-req, 10000 iters, auto-seed from current value
  goatttool -b AA:BB:CC:DD:EE:FF fuzz write -a 0x002c

  # Both write variants, 5-minute time cap, custom seed, deterministic RNG
  goatttool -b AA:BB:CC:DD:EE:FF fuzz write -a 0x002c \
      --type both --max-time 5m --seed-file seed.bin --rng-seed 42

  # Run all night with a target-reset hook
  goatttool -b AA:BB:CC:DD:EE:FF fuzz write -a 0x002c \
      --max-iter 1000000 \
      --target-reset "ssh root@plug ./toggle.sh && sleep 8"`,
		RunE: runFuzzWrite,
	}
	c.Flags().StringVarP(&fuzzWriteFlags.handle, "handle", "a", "", "target characteristic/descriptor handle")
	c.Flags().StringVarP(&fuzzWriteFlags.uuid, "uuid", "u", "", "target characteristic UUID (alternative to --handle)")
	c.Flags().StringVar(&fuzzWriteFlags.seedFile, "seed-file", "", "raw seed file (overrides auto-read)")
	c.Flags().StringVar(&fuzzWriteFlags.seedDir, "seed-dir", "", "directory of seed files; all .bin are loaded")
	c.Flags().StringVar(&fuzzWriteFlags.seedASCII, "seed", "", "ASCII seed (alternative to --seed-file)")
	c.Flags().BoolVar(&fuzzWriteFlags.noSeed, "no-seed", false, "skip auto-read; start from an empty seed")
	c.Flags().Int64Var(&fuzzWriteFlags.rngSeed, "rng-seed", 0, "RNG seed (default: time-based; printed at startup)")
	c.Flags().IntVar(&fuzzWriteFlags.maxIter, "max-iter", 10000, "iteration cap (0 = unlimited)")
	c.Flags().DurationVar(&fuzzWriteFlags.maxTime, "max-time", 0, "wall-clock cap (e.g. 30m, 8h)")
	c.Flags().IntVar(&fuzzWriteFlags.maxValueLen, "max-value-len", 244, "hard cap on mutated input length (244 = MTU 247 - 3 ATT bytes)")
	c.Flags().StringVar(&fuzzWriteFlags.types, "type", "req", "write variant(s): req | cmd | both")
	c.Flags().StringVar(&fuzzWriteFlags.livenessHandle, "liveness-handle", "", "override auto-detected liveness handle")
	c.Flags().IntVar(&fuzzWriteFlags.livenessEvery, "liveness-every", 10, "probe target liveness every N iterations")
	c.Flags().BoolVar(&fuzzWriteFlags.noLiveness, "no-liveness", false, "disable liveness probing entirely (disconnect is the only crash signal)")
	c.Flags().StringVar(&fuzzWriteFlags.targetReset, "target-reset", "", "shell command to reset the target after consecutive liveness failures")
	c.Flags().IntVar(&fuzzWriteFlags.targetResetAfter, "target-reset-after", 3, "fire --target-reset after this many consecutive liveness failures")
	c.Flags().StringVar(&fuzzWriteFlags.outDir, "out", "", "corpus output directory (default ./fuzz-out-<ISO>/)")
	c.Flags().BoolVar(&fuzzWriteFlags.noStateFeedback, "no-state-feedback", false, "treat every input as parentless; disable AFLNet-style queue")
	return c
}

func runFuzzWrite(cmd *cobra.Command, args []string) error {
	if fuzzWriteFlags.handle == "" && fuzzWriteFlags.uuid == "" {
		return fmt.Errorf("supply -a/--handle or -u/--uuid")
	}
	addr, err := requireBdaddr()
	if err != nil {
		return err
	}

	ops, err := parseFuzzTypes(fuzzWriteFlags.types)
	if err != nil {
		return err
	}

	rngSeed := fuzzWriteFlags.rngSeed
	if rngSeed == 0 {
		rngSeed = time.Now().UnixNano()
	}

	outDir := fuzzWriteFlags.outDir
	if outDir == "" {
		outDir = fmt.Sprintf("fuzz-out-%s", time.Now().UTC().Format("20060102T150405Z"))
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// Connect once to read the seed and pin the target handle.
	statusf("opening session to %s", addr)
	openCtx, openCancel := ctxWithRootTimeout()
	defer openCancel()
	sess, err := openSession(openCtx, addr, true)
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	target, err := resolveChar(sess, fuzzWriteFlags.handle, fuzzWriteFlags.uuid)
	if err != nil {
		sess.close()
		return err
	}

	// Pick the liveness handle: explicit > first readable char in the tree.
	livenessHandle, err := pickLivenessHandle(sess, target.Handle, fuzzWriteFlags.livenessHandle)
	if err != nil && !fuzzWriteFlags.noLiveness {
		sess.close()
		return fmt.Errorf("liveness probe selection: %w (use --no-liveness to skip)", err)
	}

	// Gather seeds.
	seeds, err := loadSeeds(sess, target)
	if err != nil {
		sess.close()
		return fmt.Errorf("seed corpus: %w", err)
	}

	// Set up output and trace.
	c, err := corpus.New(outDir)
	if err != nil {
		sess.close()
		return err
	}
	tr, err := trace.New(filepath.Join(outDir, "trace.jsonl"))
	if err != nil {
		sess.close()
		return err
	}
	defer tr.Close()

	// Build harness.
	h := &bluezHarness{
		addr:           addr,
		targetHandle:   target.Handle,
		livenessHandle: livenessHandle,
		resetCmd:       fuzzWriteFlags.targetReset,
		noLiveness:     fuzzWriteFlags.noLiveness,
		writeTimeout:   time.Duration(root.timeout) * time.Second,
		// take ownership of the open session
		sess:       sess,
		targetPath: target.Path,
	}
	defer h.Close()

	// MaxLen cap should never exceed the negotiated MTU - 3.
	maxLen := fuzzWriteFlags.maxValueLen
	if mtu, err := sess.conn.Characteristic(target.Path).MTU(); err == nil && mtu > 3 {
		cap := int(mtu) - 3
		if maxLen <= 0 || cap < maxLen {
			maxLen = cap
		}
	}

	mutCfg := mutate.New(rngSeed, maxLen)

	statusf("target=0x%04x liveness=0x%04x seeds=%d rng-seed=%d out=%s",
		target.Handle, livenessHandle, len(seeds), rngSeed, outDir)

	livenessEvery := fuzzWriteFlags.livenessEvery
	if fuzzWriteFlags.noLiveness {
		livenessEvery = 0
	}

	eng := &engine.Engine{
		H:       h,
		Mutator: mutCfg,
		Corpus:  c,
		Oracle:  oracle.New(),
		Trace:   tr,
		Cfg: engine.Config{
			Ops:             ops,
			MaxIter:         fuzzWriteFlags.maxIter,
			MaxTime:         fuzzWriteFlags.maxTime,
			LivenessEvery:   livenessEvery,
			ResetAfter:      fuzzWriteFlags.targetResetAfter,
			RNGSeed:         rngSeed,
			MaxValueLen:     maxLen,
			Seeds:           seeds,
			NoStateFeedback: fuzzWriteFlags.noStateFeedback,
			Status: func(s string, a ...interface{}) {
				statusf(s, a...)
			},
		},
	}

	// Write the run-meta header before the loop so a crashed process still
	// leaves something useful behind.
	startMeta := fuzzRunMeta{
		Target:      addr,
		CharHandle:  fmt.Sprintf("0x%04x", target.Handle),
		Ops:         strings.Join(opsToStrings(ops), ","),
		RNGSeed:     rngSeed,
		StartedAt:   time.Now().UTC().Format(time.RFC3339),
		MaxIter:     fuzzWriteFlags.maxIter,
		MaxTime:     fuzzWriteFlags.maxTime.String(),
		MaxValueLen: maxLen,
	}
	_ = c.WriteRunMeta(startMeta)

	stats, runErr := eng.Run(ctx)

	endMeta := startMeta
	endMeta.EndedAt = time.Now().UTC().Format(time.RFC3339)
	endMeta.Iterations = stats.Iter
	endMeta.Crashes = stats.Crashes
	endMeta.Hangs = stats.Hangs
	endMeta.QueueSize = stats.Queue
	endMeta.States = stats.States
	endMeta.Duration = stats.Duration.String()
	_ = c.WriteRunMeta(endMeta)

	if runErr != nil {
		failf("engine returned: %v", runErr)
	}
	statusf("done iter=%d states=%d queue=%d crashes=%d hangs=%d elapsed=%s",
		stats.Iter, stats.States, stats.Queue, stats.Crashes, stats.Hangs,
		stats.Duration.Round(time.Second))
	statusf("results in %s", outDir)
	return nil
}

type fuzzRunMeta struct {
	Target      string `json:"target"`
	CharHandle  string `json:"char"`
	Ops         string `json:"ops"`
	RNGSeed     int64  `json:"rng_seed"`
	StartedAt   string `json:"started_at"`
	EndedAt     string `json:"ended_at,omitempty"`
	Iterations  int    `json:"iterations,omitempty"`
	Crashes     int    `json:"crashes,omitempty"`
	Hangs       int    `json:"hangs,omitempty"`
	QueueSize   int    `json:"queue_size,omitempty"`
	States      int    `json:"states,omitempty"`
	Duration    string `json:"duration,omitempty"`
	MaxIter     int    `json:"max_iter,omitempty"`
	MaxTime     string `json:"max_time,omitempty"`
	MaxValueLen int    `json:"max_value_len,omitempty"`
}

// parseFuzzTypes resolves the --type flag into engine.Op values.
func parseFuzzTypes(s string) ([]engine.Op, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "req":
		return []engine.Op{engine.OpWriteReq}, nil
	case "cmd":
		return []engine.Op{engine.OpWriteCmd}, nil
	case "both":
		return []engine.Op{engine.OpWriteReq, engine.OpWriteCmd}, nil
	}
	// also accept comma-separated lists for future extension
	var ops []engine.Op
	for _, tok := range strings.Split(s, ",") {
		op, ok := engine.ParseOp(strings.TrimSpace(tok))
		if !ok {
			return nil, fmt.Errorf("--type: unknown variant %q (try req|cmd|both)", tok)
		}
		ops = append(ops, op)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("--type: empty")
	}
	return ops, nil
}

func opsToStrings(ops []engine.Op) []string {
	out := make([]string, len(ops))
	for i, o := range ops {
		out[i] = o.String()
	}
	return out
}

// loadSeeds assembles the initial parent pool: --seed-file or --seed-dir
// or --seed take precedence over auto-read.  --no-seed forces an empty
// initial pool.  In the auto path, we read the current value of the
// target characteristic — that's the "natural" payload the device
// understands, and the cheapest path to interesting mutations.
func loadSeeds(s *session, target bluez.GattObject) ([][]byte, error) {
	var seeds [][]byte
	if fuzzWriteFlags.seedFile != "" {
		b, err := os.ReadFile(fuzzWriteFlags.seedFile)
		if err != nil {
			return nil, err
		}
		seeds = append(seeds, b)
	}
	if fuzzWriteFlags.seedDir != "" {
		entries, err := os.ReadDir(fuzzWriteFlags.seedDir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(fuzzWriteFlags.seedDir, e.Name()))
			if err != nil {
				return nil, err
			}
			seeds = append(seeds, b)
		}
	}
	if fuzzWriteFlags.seedASCII != "" {
		seeds = append(seeds, []byte(fuzzWriteFlags.seedASCII))
	}
	if len(seeds) == 0 && !fuzzWriteFlags.noSeed {
		// Auto-read the target's current value (if readable). Best effort:
		// targets that don't advertise read get an empty seed.
		if propsCan(target.Flags, "read") {
			v, err := s.conn.Characteristic(target.Path).ReadValue(0)
			if err == nil {
				seeds = append(seeds, v)
			} else {
				logf("auto-read seed failed (%v); starting with empty seed", err)
			}
		} else {
			logf("target does not advertise 'read'; starting with empty seed")
		}
	}
	return seeds, nil
}

// pickLivenessHandle returns the handle to probe between iterations.
// Explicit > first readable characteristic in the tree (excluding the
// target itself, since reading the target after a fuzz write would
// confuse the oracle).
func pickLivenessHandle(s *session, targetHandle uint16, explicit string) (uint16, error) {
	if explicit != "" {
		return parseHandle(explicit)
	}
	if s.tree == nil {
		return 0, errors.New("GATT tree not enumerated")
	}
	var best uint16
	bestSet := false
	for h, obj := range s.tree.ByHandle {
		if obj.Kind != "characteristic" {
			continue
		}
		if h == targetHandle {
			continue
		}
		if !propsCan(obj.Flags, "read") {
			continue
		}
		if !bestSet || h < best {
			best = h
			bestSet = true
		}
	}
	if !bestSet {
		return 0, errors.New("no readable characteristic found for liveness probe")
	}
	return best, nil
}

// ---------------------- BlueZ harness ----------------------

// bluezHarness drives writes through the BlueZ D-Bus API (Layer A) — same
// path as the `write` subcommand. Sufficient for write-with-response and
// write-without-response. Multi-PDU Prepare/Execute writes need raw
// L2CAP and ship in Phase 1b.
type bluezHarness struct {
	addr           string
	targetHandle   uint16
	livenessHandle uint16
	resetCmd       string
	noLiveness     bool
	writeTimeout   time.Duration

	sess       *session
	targetPath dbus.ObjectPath
	livePath   dbus.ObjectPath
}

func (h *bluezHarness) Write(ctx context.Context, op engine.Op, value []byte) engine.WriteResult {
	if h.sess == nil {
		return engine.WriteResult{Resp: oracle.Response{Disconnected: true}, Err: errors.New("no live session")}
	}

	var wt bluez.WriteType
	switch op {
	case engine.OpWriteReq:
		wt = bluez.WriteRequest
	case engine.OpWriteCmd:
		wt = bluez.WriteCommand
	default:
		return engine.WriteResult{
			Resp: oracle.Response{},
			Err:  fmt.Errorf("BlueZ Layer A harness does not support op %s (use --raw / Phase 1b)", op),
		}
	}

	werr := h.sess.conn.Characteristic(h.targetPath).WriteValue(value, wt)

	resp := oracle.Response{}
	switch {
	case werr == nil:
		// Successful write. For req, BlueZ confirms Write Response (0x13).
		// For cmd, BlueZ accepts and returns immediately — no PDU back.
		if op == engine.OpWriteReq {
			resp.Opcode = 0x13
		}
	default:
		// Differentiate disconnect (link gone) from in-band ATT error.
		if connected, perr := h.sess.device.Connected(); perr == nil && !connected {
			resp.Disconnected = true
		} else {
			resp.Opcode = 0x01
			resp.ErrCode = classifyBluezError(werr.Error())
		}
	}
	return engine.WriteResult{Resp: resp, Err: nil}
}

func (h *bluezHarness) Liveness(ctx context.Context) error {
	if h.noLiveness {
		return nil
	}
	if h.livePath == "" {
		// Resolve once and cache. Tree is populated at session open.
		obj, ok := h.sess.tree.ByHandle[h.livenessHandle]
		if !ok {
			return fmt.Errorf("liveness handle 0x%04x not in tree", h.livenessHandle)
		}
		h.livePath = obj.Path
	}
	_, err := h.sess.conn.Characteristic(h.livePath).ReadValue(0)
	return err
}

func (h *bluezHarness) Reset(ctx context.Context) error {
	if h.resetCmd == "" {
		return errors.New("--target-reset not set; cannot recover from liveness loss")
	}
	logf("firing --target-reset hook: %s", h.resetCmd)
	cm := exec.CommandContext(ctx, "sh", "-c", h.resetCmd)
	cm.Stdout = os.Stderr
	cm.Stderr = os.Stderr
	if err := cm.Run(); err != nil {
		return fmt.Errorf("reset command exited %w", err)
	}

	// Tear down stale session, reconnect, re-resolve handles.
	h.sess.close()
	openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	s, err := openSession(openCtx, h.addr, true)
	if err != nil {
		return fmt.Errorf("reconnect after reset: %w", err)
	}
	obj, ok := s.tree.ByHandle[h.targetHandle]
	if !ok {
		s.close()
		return fmt.Errorf("target handle 0x%04x not present in tree post-reset", h.targetHandle)
	}
	h.sess = s
	h.targetPath = obj.Path
	h.livePath = "" // re-resolve on next Liveness
	statusf("target reconnected after reset")
	return nil
}

func (h *bluezHarness) Close() error {
	if h.sess != nil {
		h.sess.close()
		h.sess = nil
	}
	return nil
}

// classifyBluezError extracts a synthetic ATT error code from a BlueZ
// dbus error message. The BlueZ-to-ATT mapping is loose; we recognise
// the common patterns and fall back to 0xFF for "unknown error". The
// goal isn't perfect fidelity — it's enough discrimination that the
// oracle's state hash treats different error families as different
// states.
//
// 0xFE is reserved for "looks like a transient transport error" so it
// doesn't collide with real ATT codes (which are 0x01..0x11 plus
// application-specific 0x80..0xFF — but BlueZ never surfaces those raw).
var attErrCodeRe = regexp.MustCompile(`0x([0-9a-fA-F]{2})`)

func classifyBluezError(msg string) uint8 {
	if m := attErrCodeRe.FindStringSubmatch(msg); m != nil {
		v, err := strconv.ParseUint(m[1], 16, 8)
		if err == nil && v > 0 && v <= 0x11 {
			return uint8(v)
		}
	}
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "not connected"), strings.Contains(low, "no such file"):
		return 0xFE
	case strings.Contains(low, "not permitted"):
		return 0x03 // Write Not Permitted
	case strings.Contains(low, "not authorized"), strings.Contains(low, "unauthorized"):
		return 0x08 // Insufficient Authorization
	case strings.Contains(low, "not authenticated"):
		return 0x05 // Insufficient Authentication
	case strings.Contains(low, "invalid attribute value length"):
		return 0x0D
	case strings.Contains(low, "in progress"):
		return 0x0E // Unlikely Error (transient)
	}
	return 0xFF
}
