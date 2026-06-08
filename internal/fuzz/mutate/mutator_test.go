package mutate

import (
	"bytes"
	"testing"
)

func TestDeterministicWithSeed(t *testing.T) {
	seed := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	m1 := New(42, 0)
	m2 := New(42, 0)
	for i := 0; i < 100; i++ {
		a := m1.Mutate(seed, nil)
		b := m2.Mutate(seed, nil)
		if !bytes.Equal(a, b) {
			t.Fatalf("iter %d: same seed produced different outputs:\n  a=%x\n  b=%x", i, a, b)
		}
	}
}

func TestRespectsMaxLen(t *testing.T) {
	seed := bytes.Repeat([]byte{0x41}, 32)
	m := New(7, 20)
	for i := 0; i < 500; i++ {
		out := m.Mutate(seed, nil)
		if len(out) > 20 {
			t.Fatalf("iter %d: output length %d exceeds MaxLen=20", i, len(out))
		}
	}
}

func TestProducesSomeChange(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAA}, 32)
	m := New(1, 64)
	diffs := 0
	for i := 0; i < 200; i++ {
		out := m.Mutate(seed, nil)
		if !bytes.Equal(out, seed) {
			diffs++
		}
	}
	if diffs < 100 {
		t.Fatalf("expected at least 50%% of mutations to change the input, got %d/200", diffs)
	}
}

func TestEmptySeed(t *testing.T) {
	m := New(99, 32)
	for i := 0; i < 50; i++ {
		_ = m.Mutate(nil, nil)
	}
}

func TestSplice(t *testing.T) {
	a := []byte("aaaaaaaaaaaaaaaa")
	b := []byte("bbbbbbbbbbbbbbbb")
	m := New(13, 64)
	corpus := [][]byte{a, b}
	mixed := 0
	for i := 0; i < 500; i++ {
		out := m.Mutate(a, corpus)
		if bytes.Contains(out, []byte("bbb")) {
			mixed++
		}
	}
	if mixed == 0 {
		t.Fatalf("splice never copied bytes from the corpus pool across %d iterations", 500)
	}
}
