// Package corpus persists fuzzing inputs to disk in an AFL/libfuzzer-style
// directory layout. The engine writes here as it discovers new states and
// crashes; `caeruleus fuzz replay` reads from here to reproduce a finding.
//
// Layout:
//
//	dir/
//	  corpus/    one file per accepted input (parent pool)
//	  queue/     inputs that produced a new oracle state (pending)
//	  crashes/   inputs that triggered a crash signal (disconnect, fatal)
//	  hangs/     inputs that triggered liveness loss with failed reset
//	  run.json   run metadata (written at startup, updated at end)
//	  trace.jsonl
//
// Filenames are sha1(input)[:16].bin. A sidecar .json with the same stem
// holds per-input metadata (iteration, response opcode, etc.) — useful
// for triage but optional.
package corpus

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Category names — also the subdir names.
const (
	CatCorpus  = "corpus"
	CatQueue   = "queue"
	CatCrashes = "crashes"
	CatHangs   = "hangs"
)

var allCategories = []string{CatCorpus, CatQueue, CatCrashes, CatHangs}

// Corpus is the on-disk root of a fuzzing run.
type Corpus struct {
	Dir string
}

// New creates the directory layout under dir. It's safe to call against
// an existing dir (idempotent).
func New(dir string) (*Corpus, error) {
	for _, sub := range allCategories {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", sub, err)
		}
	}
	return &Corpus{Dir: dir}, nil
}

// ID returns the corpus-internal identifier for an input (sha1 prefix).
func ID(input []byte) string {
	h := sha1.Sum(input)
	return hex.EncodeToString(h[:8])
}

// Add writes input to category and optionally a sidecar meta JSON.
// Returns the ID. If the file already exists, it's not rewritten.
func (c *Corpus) Add(category string, input []byte, meta interface{}) (string, error) {
	id := ID(input)
	path := filepath.Join(c.Dir, category, id+".bin")
	if _, err := os.Stat(path); err == nil {
		return id, nil
	}
	if err := os.WriteFile(path, input, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	if meta != nil {
		mp := filepath.Join(c.Dir, category, id+".json")
		mb, err := json.MarshalIndent(meta, "", "  ")
		if err == nil {
			_ = os.WriteFile(mp, mb, 0o644)
		}
	}
	return id, nil
}

// Load returns the byte contents of every input in category, in
// filename order (stable).
func (c *Corpus) Load(category string) ([][]byte, error) {
	dir := filepath.Join(c.Dir, category)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	out := make([][]byte, 0, len(names))
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// LoadFileOrDir returns inputs from a single file or every .bin under a
// directory. Used by `fuzz replay` so the user can point at one crash or
// at an entire crashes/ folder.
func LoadFileOrDir(path string) ([][]byte, []string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !st.IsDir() {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		return [][]byte{b}, []string{filepath.Base(path)}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, nil, err
	}
	var inputs [][]byte
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(path, e.Name()))
		if err != nil {
			return nil, nil, err
		}
		inputs = append(inputs, b)
		names = append(names, e.Name())
	}
	return inputs, names, nil
}

// WriteRunMeta serializes meta to dir/run.json.
func (c *Corpus) WriteRunMeta(meta interface{}) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.Dir, "run.json"), b, 0o644)
}
