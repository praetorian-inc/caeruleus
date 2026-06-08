// Adapted from github.com/dvyukov/go-fuzz/go-fuzz/mutator.go.
//
// Upstream notice:
//
//   Copyright 2015 go-fuzz project authors. All rights reserved.
//   Use of this source code is governed by Apache 2 LICENSE that can be
//   found in the LICENSE file.
//
// See PROVENANCE.md for the list of changes (math/rand instead of pcg,
// ROData removed, literal mutators removed, types exported).

// Package mutate provides byte-level mutators for blackbox fuzzing. It
// is a vendored, adapted copy of go-fuzz's mutator with the go-fuzz
// instrumentation/corpus-scoring machinery removed — the engine picks
// the parent, this package just transforms bytes.
package mutate

import (
	"encoding/binary"
	"math/bits"
	"math/rand"
	"strconv"
)

// Mutator mutates byte strings using a fixed family of strategies
// (bitflip, byte/word/dword arith, interesting-value substitution,
// range edits, splice across the corpus, ASCII number replacement).
//
// Not safe for concurrent use — one Mutator per goroutine. Seed via
// New so reproducibility is under the caller's control.
type Mutator struct {
	r      *rand.Rand
	MaxLen int    // upper bound on output length; 0 disables the cap
	Last   string // name of the most recent mutation (for trace logs)
}

// New creates a Mutator with the given seed. maxLen caps output length
// (set to 0 for no cap; BLE ATT writes are typically capped by MTU
// anyway, so pass MTU-3 or similar).
func New(seed int64, maxLen int) *Mutator {
	return &Mutator{r: rand.New(rand.NewSource(seed)), MaxLen: maxLen}
}

// Mutate returns a new byte slice derived from data. corpus is an
// optional pool of other inputs used by splice/insert-part-of mutators
// (may be empty). The number of mutations applied per call follows
// the same 1+Exp2() distribution as upstream go-fuzz, so most calls
// apply 1 mutation but some chain many for "havoc" effect.
func (m *Mutator) Mutate(data []byte, corpus [][]byte) []byte {
	res := make([]byte, len(data))
	copy(res, data)
	nm := 1 + m.exp2()
	for iter := 0; iter < nm; iter++ {
		switch m.rand(18) {
		case 0:
			// Remove a range of bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			pos0 := m.rand(len(res))
			pos1 := pos0 + m.chooseLen(len(res)-pos0)
			copy(res[pos0:], res[pos1:])
			res = res[:len(res)-(pos1-pos0)]
			m.Last = "remove"
		case 1:
			// Insert a range of random bytes.
			pos := m.rand(len(res) + 1)
			n := m.chooseLen(10)
			for i := 0; i < n; i++ {
				res = append(res, 0)
			}
			copy(res[pos+n:], res[pos:])
			for i := 0; i < n; i++ {
				res[pos+i] = byte(m.rand(256))
			}
			m.Last = "insert-rand"
		case 2:
			// Duplicate a range of bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			src := m.rand(len(res))
			dst := m.rand(len(res))
			for dst == src {
				dst = m.rand(len(res))
			}
			n := m.chooseLen(len(res) - src)
			tmp := make([]byte, n)
			copy(tmp, res[src:])
			for i := 0; i < n; i++ {
				res = append(res, 0)
			}
			copy(res[dst+n:], res[dst:])
			for i := 0; i < n; i++ {
				res[dst+i] = tmp[i]
			}
			m.Last = "duplicate"
		case 3:
			// Copy a range of bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			src := m.rand(len(res))
			dst := m.rand(len(res))
			for dst == src {
				dst = m.rand(len(res))
			}
			n := m.chooseLen(len(res) - src)
			if dst+n > len(res) || src+n > len(res) {
				iter--
				continue
			}
			copy(res[dst:], res[src:src+n])
			m.Last = "copy"
		case 4:
			// Bit flip. Spooky!
			if len(res) == 0 {
				iter--
				continue
			}
			pos := m.rand(len(res))
			res[pos] ^= 1 << uint(m.rand(8))
			m.Last = "bitflip"
		case 5:
			// Set a byte to a random value.
			if len(res) == 0 {
				iter--
				continue
			}
			pos := m.rand(len(res))
			res[pos] ^= byte(m.rand(255)) + 1
			m.Last = "byte-set"
		case 6:
			// Swap 2 bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			src := m.rand(len(res))
			dst := m.rand(len(res))
			for dst == src {
				dst = m.rand(len(res))
			}
			res[src], res[dst] = res[dst], res[src]
			m.Last = "swap"
		case 7:
			// Add/subtract from a byte.
			if len(res) == 0 {
				iter--
				continue
			}
			pos := m.rand(len(res))
			v := byte(m.rand(35) + 1)
			if m.bool() {
				res[pos] += v
			} else {
				res[pos] -= v
			}
			m.Last = "arith8"
		case 8:
			// Add/subtract from a uint16.
			if len(res) < 2 {
				iter--
				continue
			}
			pos := m.rand(len(res) - 1)
			buf := res[pos:]
			v := uint16(m.rand(35) + 1)
			if m.bool() {
				v = 0 - v
			}
			enc := m.randByteOrder()
			enc.PutUint16(buf, enc.Uint16(buf)+v)
			m.Last = "arith16"
		case 9:
			// Add/subtract from a uint32.
			if len(res) < 4 {
				iter--
				continue
			}
			pos := m.rand(len(res) - 3)
			buf := res[pos:]
			v := uint32(m.rand(35) + 1)
			if m.bool() {
				v = 0 - v
			}
			enc := m.randByteOrder()
			enc.PutUint32(buf, enc.Uint32(buf)+v)
			m.Last = "arith32"
		case 10:
			// Add/subtract from a uint64.
			if len(res) < 8 {
				iter--
				continue
			}
			pos := m.rand(len(res) - 7)
			buf := res[pos:]
			v := uint64(m.rand(35) + 1)
			if m.bool() {
				v = 0 - v
			}
			enc := m.randByteOrder()
			enc.PutUint64(buf, enc.Uint64(buf)+v)
			m.Last = "arith64"
		case 11:
			// Replace a byte with an interesting value.
			if len(res) == 0 {
				iter--
				continue
			}
			pos := m.rand(len(res))
			res[pos] = byte(interesting8[m.rand(len(interesting8))])
			m.Last = "int8"
		case 12:
			// Replace an uint16 with an interesting value.
			if len(res) < 2 {
				iter--
				continue
			}
			pos := m.rand(len(res) - 1)
			buf := res[pos:]
			v := uint16(interesting16[m.rand(len(interesting16))])
			m.randByteOrder().PutUint16(buf, v)
			m.Last = "int16"
		case 13:
			// Replace an uint32 with an interesting value.
			if len(res) < 4 {
				iter--
				continue
			}
			pos := m.rand(len(res) - 3)
			buf := res[pos:]
			v := uint32(interesting32[m.rand(len(interesting32))])
			m.randByteOrder().PutUint32(buf, v)
			m.Last = "int32"
		case 14:
			// Replace an ASCII digit with another digit.
			var digits []int
			for i, v := range res {
				if v >= '0' && v <= '9' {
					digits = append(digits, i)
				}
			}
			if len(digits) == 0 {
				iter--
				continue
			}
			pos := m.rand(len(digits))
			was := res[digits[pos]]
			now := was
			for was == now {
				now = byte(m.rand(10)) + '0'
			}
			res[digits[pos]] = now
			m.Last = "digit"
		case 15:
			// Replace a multi-byte ASCII number with another number.
			type arange struct {
				start int
				end   int
			}
			var numbers []arange
			start := -1
			for i, v := range res {
				if (v >= '0' && v <= '9') || (start == -1 && v == '-') {
					if start == -1 {
						start = i
					} else if i == len(res)-1 {
						if i-start > 0 {
							numbers = append(numbers, arange{start, i + 1})
						}
					}
				} else {
					if start != -1 && i-start > 1 {
						numbers = append(numbers, arange{start, i})
						start = -1
					}
				}
			}
			if len(numbers) == 0 {
				iter--
				continue
			}
			var v int64
			switch m.rand(4) {
			case 0:
				v = int64(m.rand(1000))
			case 1:
				v = m.randbig()
			case 2:
				v = m.randbig() * m.randbig()
			case 3:
				v = -m.randbig()
			}
			rg := numbers[m.rand(len(numbers))]
			if res[rg.start] == '-' {
				v *= -1
			}
			str := strconv.FormatInt(v, 10)
			tmp := make([]byte, len(res)-(rg.end-rg.start)+len(str))
			copy(tmp, res[:rg.start])
			copy(tmp[rg.start:], str)
			copy(tmp[rg.start+len(str):], res[rg.end:])
			res = tmp
			m.Last = "number"
		case 16:
			// Splice another input.
			if len(res) < 4 || len(corpus) < 2 {
				iter--
				continue
			}
			other := corpus[m.rand(len(corpus))]
			if len(other) < 4 || sameBacking(res, other) {
				iter--
				continue
			}
			idx0 := 0
			for idx0 < len(res) && idx0 < len(other) && res[idx0] == other[idx0] {
				idx0++
			}
			idx1 := 0
			for idx1 < len(res) && idx1 < len(other) && res[len(res)-idx1-1] == other[len(other)-idx1-1] {
				idx1++
			}
			diff := min(len(res)-idx0-idx1, len(other)-idx0-idx1)
			if diff < 4 {
				iter--
				continue
			}
			copy(res[idx0:idx0+m.rand(diff-2)+1], other[idx0:])
			m.Last = "splice"
		case 17:
			// Insert a part of another input.
			if len(res) < 4 || len(corpus) < 2 {
				iter--
				continue
			}
			other := corpus[m.rand(len(corpus))]
			if len(other) < 4 || sameBacking(res, other) {
				iter--
				continue
			}
			pos0 := m.rand(len(res) + 1)
			pos1 := m.rand(len(other) - 2)
			n := m.chooseLen(len(other)-pos1-2) + 2
			for i := 0; i < n; i++ {
				res = append(res, 0)
			}
			copy(res[pos0+n:], res[pos0:])
			for i := 0; i < n; i++ {
				res[pos0+i] = other[pos1+i]
			}
			m.Last = "insert-other"
		}
	}
	if m.MaxLen > 0 && len(res) > m.MaxLen {
		res = res[:m.MaxLen]
	}
	return res
}

// chooseLen biases toward short ranges (same distribution as upstream).
func (m *Mutator) chooseLen(n int) int {
	switch x := m.rand(100); {
	case x < 90:
		return m.rand(min(8, n)) + 1
	case x < 99:
		return m.rand(min(32, n)) + 1
	default:
		return m.rand(n) + 1
	}
}

func (m *Mutator) rand(n int) int {
	if n <= 0 {
		return 0
	}
	return m.r.Intn(n)
}

func (m *Mutator) bool() bool                   { return m.r.Intn(2) == 0 }
func (m *Mutator) randbig() int64               { return int64(m.r.Uint32() >> 2) }
func (m *Mutator) randByteOrder() binary.ByteOrder {
	if m.bool() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// exp2 returns a small integer biased toward 0: trailing zero count of
// a random 32-bit value. 50% return 0, 25% return 1, 12.5% return 2, ...
// Same distribution as go-fuzz's pcg.Exp2.
func (m *Mutator) exp2() int {
	return bits.TrailingZeros32(m.r.Uint32() | 1<<31)
}

// sameBacking reports whether two slices share the same underlying array
// at index 0 — used to avoid splicing an input with itself.
func sameBacking(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return &a[0] == &b[0]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var (
	interesting8  = []int8{-128, -1, 0, 1, 16, 32, 64, 100, 127}
	interesting16 = []int16{-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767}
	interesting32 = []int32{-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647}
)

func init() {
	for _, v := range interesting8 {
		interesting16 = append(interesting16, int16(v))
	}
	for _, v := range interesting16 {
		interesting32 = append(interesting32, int32(v))
	}
}
