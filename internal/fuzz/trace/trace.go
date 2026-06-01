// Package trace writes one JSON record per fuzz iteration. The trace
// file is intentionally line-delimited (JSONL) so it can be tail'd, awk'd,
// and jq'd by hand during long-running engagements.
package trace

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Record is one iteration's log entry. Fields are tagged short because
// these files can be millions of lines on long runs.
type Record struct {
	Iter     int    `json:"i"`
	Mut      string `json:"mut,omitempty"`
	ParentID string `json:"parent,omitempty"`
	InputID  string `json:"id"`
	Input    string `json:"input"` // hex
	Op       string `json:"op"`    // write_req | write_cmd | prep | exec | ...

	// Response fields — all optional.
	RespOp  string `json:"resp_op,omitempty"`
	ErrCode string `json:"err,omitempty"`
	RespLen int    `json:"resp_len,omitempty"`
	RespHex string `json:"resp_hex,omitempty"`

	// Engine state.
	Live     bool  `json:"live"`
	NewState bool  `json:"new_state,omitempty"`
	Crash    bool  `json:"crash,omitempty"`
	Hang     bool  `json:"hang,omitempty"`
	MS       int64 `json:"ms"`
	Err      string `json:"err_msg,omitempty"`
}

// HexInput is a helper for callers that don't want to encode by hand.
func HexInput(b []byte) string { return hex.EncodeToString(b) }

// Writer writes records to a JSONL file. Buffered; Close flushes.
type Writer struct {
	f *os.File
	w *bufio.Writer
}

// New opens path for writing (truncating if it exists).
func New(path string) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create trace: %w", err)
	}
	return &Writer{f: f, w: bufio.NewWriterSize(f, 1<<16)}, nil
}

// Write serializes rec as JSON + newline.
func (t *Writer) Write(rec Record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := t.w.Write(b); err != nil {
		return err
	}
	return t.w.WriteByte('\n')
}

// Close flushes and closes the underlying file.
func (t *Writer) Close() error {
	if t == nil || t.f == nil {
		return nil
	}
	if err := t.w.Flush(); err != nil {
		_ = t.f.Close()
		return err
	}
	return t.f.Close()
}

// Iterator streams Records from an existing trace.jsonl.
type Iterator struct {
	r *bufio.Reader
	f *os.File
}

// Open returns an iterator over path.
func Open(path string) (*Iterator, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &Iterator{r: bufio.NewReaderSize(f, 1<<16), f: f}, nil
}

// Next returns the next Record. io.EOF marks the end.
func (it *Iterator) Next() (Record, error) {
	line, err := it.r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return Record{}, err
	}
	var rec Record
	if jerr := json.Unmarshal(line, &rec); jerr != nil {
		return Record{}, jerr
	}
	if err == io.EOF {
		// Last line without trailing newline — return it, signal EOF next call.
		return rec, nil
	}
	return rec, nil
}

// Close releases the underlying file.
func (it *Iterator) Close() error {
	if it == nil || it.f == nil {
		return nil
	}
	return it.f.Close()
}
