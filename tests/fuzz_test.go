// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Fuzz targets for the wire decoders. Run with:
//
//	go test ./tests/ -fuzz FuzzTxDecode -fuzztime 30s
//	go test ./tests/ -fuzz FuzzBlockDecode -fuzztime 30s
//
// Seed corpora are checked by the plain unit run of this file.
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee

package tests

import (
	"testing"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/transactions"
)

var fuzzParams = consensus.Defaults()

func FuzzTxDecode(f *testing.F) {
	// Seed corpus: a valid transaction encoding.
	kpTx := validSignedTx()
	f.Add(kpTx)
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00})
	f.Add(make([]byte, 200))

	f.Fuzz(func(t *testing.T, data []byte) {
		// The decoder must never panic and must never accept trailing junk.
		tx, err := transactions.Decode(data)
		if err != nil {
			return
		}
		// If it decodes, it must re-encode identically (canonical form).
		re := tx.Encode()
		if string(re) != string(data) {
			t.Fatalf("non-canonical decode: %d bytes -> %d bytes", len(data), len(re))
		}
	})
}

func FuzzBlockDecode(f *testing.F) {
	p := fuzzParams
	// Seed: a small structurally valid coinbase-only block.
	blk := &blockdag.Block{
		Header: &blockdag.Header{
			Version:    p.ProtocolVersion,
			Parents:    []cryptography.Hash{blockdag.GenesisHash(&p)},
			Time:       p.GenesisTime + 1,
			Difficulty: p.GenesisDifficulty,
		},
		Txs: []transactions.Tx{{
			Version: 1,
			Outputs: []transactions.TxOut{{
				Value:      0,
				PubKeyHash: [20]byte{},
			}},
			Aux: []byte("seed"),
		}},
	}
	blk.Header.TxMerkle = blockdag.ComputeMerkle(blk.TxIDs())
	seed, err := blockdag.EncodeBlock(blk)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add(seed[:len(seed)/2])

	f.Fuzz(func(t *testing.T, data []byte) {
		blk, err := blockdag.DecodeBlock(data, &p)
		if err != nil {
			return
		}
		// Canonical blocks must roundtrip byte-for-byte.
		re, err := blockdag.EncodeBlock(blk)
		if err != nil {
			t.Fatalf("decoded block failed to encode: %v", err)
		}
		if string(re) != string(data) {
			t.Fatal("block decode is not canonical")
		}
	})
}

func validSignedTx() []byte {
	p := fuzzParams
	tx := &transactions.Tx{
		Version: 1,
		Inputs: []transactions.TxIn{{
			PrevTx:    [32]byte{1, 2, 3},
			PrevIndex: 0,
		}},
		Outputs: []transactions.TxOut{{Value: p.DustLimit * 10, PubKeyHash: [20]byte{9}}},
	}
	return tx.Encode()
}
