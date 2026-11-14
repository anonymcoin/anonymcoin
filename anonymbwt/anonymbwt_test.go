// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package anonymbwt

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
)

// naiveSuffixOrder returns the suffix order by direct comparison — the
// reference model for property tests.
func naiveSuffixOrder(buf []byte) []int32 {
	n := len(buf)
	idx := make([]int32, n)
	for i := range idx {
		idx[i] = int32(i)
	}
	less := func(a, b int32) bool {
		x, y := buf[a:], buf[b:]
		return bytes.Compare(x, y) < 0
	}
	sort.Slice(idx, func(i, j int) bool { return less(idx[i], idx[j]) })
	return idx
}

func TestSuffixArrayMatchesNaive(t *testing.T) {
	cases := [][]byte{
		[]byte("banana"),
		[]byte("mississippi"),
		{0, 0, 0, 0, 0, 0, 0, 0},
		{1, 1, 1, 1, 2, 1, 1, 1, 1, 2},
		{0xff, 0x00, 0xff, 0x00, 0xff},
		[]byte("aaaaaaaaab"),
		{7},
	}
	rng := rand.New(rand.NewSource(2026))
	for i := 0; i < 200; i++ {
		n := 1 + rng.Intn(300)
		b := make([]byte, n)
		switch i % 3 {
		case 0:
			rng.Read(b)
		case 1: // low-entropy repetitive buffers stress rank ties
			for j := range b {
				b[j] = byte(rng.Intn(3))
			}
		case 2: // long runs
			b0 := byte(rng.Intn(256))
			for j := range b {
				b[j] = b0
			}
		}
		cases = append(cases, b)
	}
	w := NewWorkspace()
	for ci, buf := range cases {
		w.SortSuffixes(buf)
		got := make([]int32, len(buf))
		copy(got, w.sa[:len(buf)])
		want := naiveSuffixOrder(buf)
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("case %d: suffix order mismatch at %d: got %v want %v (buf len %d)",
					ci, i, got[:min(8, len(got))], want[:min(8, len(want))], len(buf))
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestDigestDeterministic(t *testing.T) {
	data := []byte("ANONYMCOIN — THE BLOCKDAG IS THE HEART — determinism vector")
	a := Digest(data)
	b := Digest(data)
	c := NewWorkspace().Digest(data)
	if a != b || a != c {
		t.Fatalf("digest not deterministic: %x %x %x", a, b, c)
	}
	t.Logf("ANONYMBWT vector: %x", a[:])
}

func TestDigestVariesWithInput(t *testing.T) {
	a := Digest([]byte("input-one"))
	b := Digest([]byte("input-two"))
	if a == b {
		t.Fatal("digest collision on trivially different inputs")
	}
}

func TestTargetAndPoWRoundtrip(t *testing.T) {
	// Difficulty 1 -> maximum target: every digest meets it.
	mt := TargetBytes(1)
	for i := 0; i < 32; i++ {
		if mt[i] != 0xff {
			t.Fatalf("difficulty 1 target byte %d = %x, want ff", i, mt[i])
		}
	}
	// Difficulty 2^32 -> top 4 bytes zero, then 28 bytes of 0xff.
	hi := TargetBytes(1 << 32)
	for i := 0; i < 4; i++ {
		if hi[i] != 0x00 {
			t.Fatalf("difficulty 2^32 target byte %d = %x, want 00", i, hi[i])
		}
	}
	if hi[4] != 0xff || hi[31] != 0xff {
		t.Fatalf("difficulty 2^32 target tail bytes: %x", hi[4:])
	}
	if !MeetsTarget([32]byte{}, mt) {
		t.Fatal("zero digest must meet difficulty-1 target")
	}
	if MeetsTarget(mt, [32]byte{}) {
		t.Fatal("max digest must not meet zero target")
	}
}

// TestMineAndVerify mines a header at a modest difficulty and verifies the
// PoW with an independent workspace.
func TestMineAndVerify(t *testing.T) {
	const difficulty = 16 // ~16 hashes expected on average
	header := make([]byte, 0, 128)
	for i := 0; i < 96; i++ {
		header = append(header, byte(i))
	}
	header = append(header, 0, 0, 0, 0, 0, 0, 0, 0) // nonce placeholder (last 8 bytes)
	target := TargetBytes(difficulty)

	w := NewWorkspace()
	found := uint64(0)
	for nonce := uint64(0); nonce < 1<<24; nonce++ {
		copy(header[len(header)-8:], uint64LE(nonce))
		d := w.Digest(header)
		if MeetsTarget(d, target) {
			found = nonce
			break
		}
	}
	if found == 0 && !MeetsTarget(w.Digest(header), target) {
		t.Fatal("no nonce found at trivial difficulty")
	}
	// Independent verification.
	other := NewWorkspace()
	copy(header[len(header)-8:], uint64LE(found))
	d := other.Digest(header)
	if !MeetsTarget(d, target) {
		t.Fatal("mined solution failed independent verification")
	}
	// A different nonce must (almost surely) fail at difficulty 2^256/16.
	copy(header[len(header)-8:], uint64LE(found+1))
	if MeetsTarget(other.Digest(header), target) {
		t.Log("benign: adjacent nonce also met the low target")
	}
}

func uint64LE(v uint64) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(v >> (8 * i))
	}
	return out
}

// BenchmarkDigestFull measures the full ANONYMBWT-1 hash on the standard
// 64 KiB path. This is THE mining hash-rate benchmark.
func BenchmarkDigestFull(b *testing.B) {
	w := NewWorkspace()
	data := make([]byte, 128)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(data[:8], uint64LE(uint64(i)))
		w.Digest(data)
	}
}

// BenchmarkSuffixSort isolates the BWT suffix sorting stage.
func BenchmarkSuffixSort(b *testing.B) {
	w := NewWorkspace()
	w.seed = [32]byte{1, 2, 3}
	w.expand()
	buf := w.buf[:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.SortSuffixes(buf)
	}
}
