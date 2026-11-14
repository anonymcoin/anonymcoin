// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package consensus

// VirtualTime implements the monotone, manipulation-bounded DAG clock.
//
// VT(B) = max( max_{p in parents(B)} VT(p),
//
//	min( blockTime(B), max_{p} VT(p) + VTDriftCap ) )
//
// Properties relied upon by consensus (see CONSENSUS.md):
//   - VT is monotonically non-decreasing along every parent edge, therefore
//     monotone along the whole DAG and along the canonical order.
//   - VT can advance by at most VTDriftCap seconds per block, bounding the
//     effect of timestamp inflation by a miner.
//   - VT(B) depends only on B's ancestors and its own block time, so it is
//     deterministic and independent of arrival order or reorgs elsewhere in
//     the DAG.
func VirtualTime(blockTime uint64, parentVTs []uint64, p *Params) uint64 {
	var maxParent uint64
	for i, vt := range parentVTs {
		if i == 0 || vt > maxParent {
			maxParent = vt
		}
	}
	vt := maxParent
	if blockTime > vt {
		vt = blockTime
		if blockTime > maxParent+p.VTDriftCap {
			vt = maxParent + p.VTDriftCap
		}
	}
	return vt
}

// Median returns the deterministic median of a uint64 slice. For even-sized
// inputs it returns the element at index (n-1)/2 of the sorted copy (the
// lower median). The input slice is not modified.
func Median(xs []uint64) uint64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	s := make([]uint64, n)
	copy(s, xs)
	// insertion sort: window sizes here are tiny (MTPWindow ~ 11)
	for i := 1; i < n; i++ {
		v := s[i]
		j := i - 1
		for j >= 0 && s[j] > v {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = v
	}
	return s[(n-1)/2]
}
