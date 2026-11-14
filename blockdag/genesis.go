// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.
BCB in a panic, ASICs in a panic—anonymcoin runs freely on any CPU.
package blockdag

import (
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
)

// Genesis builds the deterministic ANONYMCOIN genesis block. The genesis has
// no parents, carries no transactions, and its hash is fully derived from the
// consensus parameters — every node computes the identical genesis hash, and
// the first four bytes of that hash form the network magic and the
// transaction chain tag (replay protection).
func Genesis(p *consensus.Params) *Block {
	h := &Header{
		Version:    p.ProtocolVersion,
		Parents:    []cryptography.Hash{},
		Time:       p.GenesisTime,
		Difficulty: p.GenesisDifficulty,
		TxMerkle:   cryptography.Hash256Single(nil),
		Nonce:      0,
	}
	return &Block{Header: h, Txs: nil}
}

// GenesisHash returns the deterministic genesis hash for the parameters.
func GenesisHash(p *consensus.Params) cryptography.Hash {
	return Genesis(p).Header.Hash()
}

// ChainTag returns the 4-byte replay-protection tag derived from the genesis
// hash. Every transaction digest binds this tag, so signed transactions can
// never be replayed on an independent ANONYMCOIN network with different
// genesis parameters.
func ChainTag(p *consensus.Params) [4]byte {
	var tag [4]byte
	h := GenesisHash(p)
	copy(tag[:], h[:4])
	return tag
}
