// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
// BCB in a panic, ASICs in a panic, anonymous coins—run freely on any CPU.
// 

 //This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package anonymbwt implements ANONYMBWT, the original ANONYMCOIN
// proof-of-work: a CPU-oriented, memory-treading Burrows-Wheeler-transform
// hash developed as an independent fork of the AstroBWT design studied from
// its publicly available use in Kaspa (kaspad, ISC License — see
// THIRD_PARTY_NOTICES.md). No code was copied; the algorithm below was
// implemented from scratch in Go with different primitives (BLAKE2b instead
// of SHA3-256, a documented xorshift expansion, and an original
// prefix-doubling suffix sorter instead of SA-IS).
//
// Specification (ANONYMBWT-1):
//
//  1. seed  = BLAKE2b-256(input)                      (32 bytes)
//  2. buf   = expand(seed)                            (65536 bytes)
//     8 xorshift64 lanes seeded from the seed; each 64-bit word output is
//     mixed with the neighbouring lane and a golden-ratio counter; the seed
//     is re-folded into the lanes every 1024 words.
//  3. sa    = suffixArray(buf)                        (Manber-Myers prefix
//     doubling with counting sort, implicit -1 sentinel second key)
//  4. bwt[i] = buf[(sa[i] + N - 1) mod N]             (BWT of buf)
//  5. out   = BLAKE2b-256( bwt || LE32(sa[0]) || LE32(sa[N/2]) || LE32(sa[N-1]) )
//
// PoW check: out, read as a big-endian 256-bit integer, must be <= target,
// where target = floor((2^256 - 1) / difficulty).
//
// The suffix sort is branchy, data-dependent and touches ~1 MiB of working
// memory per hash, which is what makes GPU/ASIC advantages expensive while
// ordinary CPUs run it at full speed. No absolute hardware-resistance claim
// is made without benchmarking: see ANONYMBWT.md and the benchmarks in this
// package.
package anonymbwt

import (
	"encoding/binary"
	"math/big"

	"golang.org/x/crypto/blake2b"
)

// BufSize is the BWT input size in bytes (64 KiB).
const BufSize = 65536

// goldenRatio is the Knuth golden-ratio additive constant.
const goldenRatio = uint64(0x9E3779B97F4A7C15)

// Digest computes the ANONYMBWT-1 digest of data with a fresh workspace.
func Digest(data []byte) [32]byte {
	w := AcquireWorkspace()
	defer ReleaseWorkspace(w)
	return w.Digest(data)
}

// Workspace holds reusable buffers for the hot mining loop. Workspaces are
// goroutine-confined: use the Pool helpers or allocate one per worker.
type Workspace struct {
	seed  [32]byte
	buf   [BufSize]byte
	sa    []int32
	rank  []int32
	tmp   []int32
	cnt   []int32
	bwt   [BufSize]byte
	out   [32]byte
	mixin [8]byte
}

// NewWorkspace allocates a workspace.
func NewWorkspace() *Workspace {
	return &Workspace{
		sa:   make([]int32, BufSize),
		rank: make([]int32, BufSize),
		tmp:  make([]int32, BufSize),
		cnt:  make([]int32, BufSize+257),
	}
}

// pool of workspaces for transient callers.
var pool = make(chan *Workspace, 64)

// AcquireWorkspace takes a workspace from the pool or creates one.
func AcquireWorkspace() *Workspace {
	select {
	case w := <-pool:
		return w
	default:
		return NewWorkspace()
	}
}

// ReleaseWorkspace returns a workspace to the pool.
func ReleaseWorkspace(w *Workspace) {
	select {
	case pool <- w:
	default:
	}
}

// expand fills w.buf deterministically from w.seed (see package docs).
func (w *Workspace) expand() {
	var lanes [8]uint64
	for j := 0; j < 4; j++ {
		lanes[j] = binary.LittleEndian.Uint64(w.seed[j*8 : j*8+8])
	}
	for j := 4; j < 8; j++ {
		lanes[j] = binary.LittleEndian.Uint64(w.seed[(j-4)*8:(j-4)*8+8]) ^ (0xA5A5A5A5A5A5A5A5 ^ uint64(j))
	}
	const words = BufSize / 8
	for i := 0; i < words; i++ {
		j := i & 7
		x := lanes[j]
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		lanes[j] = x
		mixed := x ^ rotl64(lanes[(j+1)&7], 23) ^ uint64(i)*goldenRatio
		binary.LittleEndian.PutUint64(w.buf[i*8:], mixed)
		if i != 0 && i%1024 == 0 {
			k := (i / 1024) & 7
			lanes[k] ^= binary.LittleEndian.Uint64(w.seed[(k*8)%32 : (k*8)%32+8])
		}
	}
}

func rotl64(x uint64, k uint) uint64 { return x<<k | x>>(64-k) }

// SortSuffixes computes the suffix array of an arbitrary buffer into w.sa
// (truncated to len(buf)). Used by the mining hot path with w.buf and by
// property tests with small buffers.
func (w *Workspace) SortSuffixes(buf []byte) {
	n := int32(len(buf))
	sa, rank, tmp, cnt := w.sa, w.rank, w.tmp, w.cnt

	// Initial ranking by single byte (counting sort over 256 values).
	for i := int32(0); i < 257; i++ {
		cnt[i] = 0
	}
	for i := int32(0); i < n; i++ {
		cnt[buf[i]]++
	}
	sum := int32(0)
	for c := int32(0); c < 256; c++ {
		t := cnt[c]
		cnt[c] = sum
		sum += t
	}
	for i := int32(0); i < n; i++ {
		c := buf[i]
		sa[cnt[c]] = i
		cnt[c]++
	}
	rank[sa[0]] = 0
	for i := int32(1); i < n; i++ {
		rank[sa[i]] = rank[sa[i-1]]
		if buf[sa[i]] != buf[sa[i-1]] {
			rank[sa[i]]++
		}
	}

	// Prefix doubling until all ranks are distinct.
	for k := int32(1); rank[sa[n-1]] < n-1; k <<= 1 {
		// Sort by second key: suffixes with i+k >= n have key -1 and come
		// first; stable order otherwise inherited from sa.
		p := int32(0)
		for i := n - k; i < n; i++ {
			tmp[p] = i // suffix i has no second key
			p++
		}
		for i := int32(0); i < n; i++ {
			if sa[i] >= k {
				tmp[p] = sa[i] - k
				p++
			}
		}
		// Stable counting sort by first key (current rank).
		for i := int32(0); i < n; i++ {
			cnt[i] = 0
		}
		for i := int32(0); i < n; i++ {
			cnt[rank[i]]++
		}
		sum := int32(0)
		for i := int32(0); i < n; i++ {
			t := cnt[i]
			cnt[i] = sum
			sum += t
		}
		for i := int32(0); i < n; i++ {
			s := tmp[i]
			sa[cnt[rank[s]]] = s
			cnt[rank[s]]++
		}
		// Re-rank with the (-1) sentinel for out-of-range second keys.
		tmp[sa[0]] = 0
		for i := int32(1); i < n; i++ {
			r1, r2 := rank[sa[i]], rank[sa[i-1]]
			r1b, r2b := int32(-1), int32(-1)
			if sa[i]+k < n {
				r1b = rank[sa[i]+k]
			}
			if sa[i-1]+k < n {
				r2b = rank[sa[i-1]+k]
			}
			tmp[sa[i]] = tmp[sa[i-1]]
			if r1 != r2 || r1b != r2b {
				tmp[sa[i]]++
			}
		}
		copy(rank, tmp)
	}
}

// Digest computes the ANONYMBWT-1 digest of data using the workspace.
func (w *Workspace) Digest(data []byte) [32]byte {
	seed := blake2b.Sum256(data)
	w.seed = seed
	w.expand()
	w.SortSuffixes(w.buf[:])
	n := int32(BufSize)
	for i := int32(0); i < n; i++ {
		s := w.sa[i]
		prev := s - 1
		if prev < 0 {
			prev = n - 1
		}
		w.bwt[i] = w.buf[prev]
	}
	h, _ := blake2b.New256(nil)
	h.Write(w.bwt[:])
	var e [4]byte
	binary.LittleEndian.PutUint32(e[:], uint32(w.sa[0]))
	h.Write(e[:])
	binary.LittleEndian.PutUint32(e[:], uint32(w.sa[n/2]))
	h.Write(e[:])
	binary.LittleEndian.PutUint32(e[:], uint32(w.sa[n-1]))
	h.Write(e[:])
	copy(w.out[:], h.Sum(nil))
	return w.out
}

// TargetBytes converts a difficulty into the 32-byte big-endian PoW target:
// target = floor((2^256 - 1) / difficulty). Difficulty 1 yields the maximum
// target (testnet-friendly bootstrap difficulty).
func TargetBytes(difficulty uint64) [32]byte {
	var out [32]byte
	if difficulty == 0 {
		difficulty = 1
	}
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	t := new(big.Int).Div(max, new(big.Int).SetUint64(difficulty))
	b := t.Bytes() // big-endian, minimal length
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(out[32-len(b):], b)
	return out
}

// MeetsTarget reports whether a digest meets the target (digest as big-endian
// integer <= target).
func MeetsTarget(digest, target [32]byte) bool {
	for i := 0; i < 32; i++ {
		switch {
		case digest[i] < target[i]:
			return true
		case digest[i] > target[i]:
			return false
		}
	}
	return true // equal: meets
}
