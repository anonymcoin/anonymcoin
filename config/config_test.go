// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package config

import (
	"path/filepath"
	"testing"

	"github.com/anonymcoin/anonymcoin/consensus"
)

func TestDefaultsValid(t *testing.T) {
	c := Defaults(t.TempDir())
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	if c.P2P.Port != 8611 || c.RPC.ListenAddr != "127.0.0.1:8612" {
		t.Fatal("unexpected default ports")
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c := Defaults(dir)
	c.Mining.Enabled = true
	c.Mining.Workers = 3
	c.P2P.Peers = []PeerConfig{{
		Address:           "peer.example.org:8611",
		Kind:              KindTCP,
		CertFingerprint:   "AN00000000000000000000000000000000",
		FalconFingerprint: "AN11111111111111111111111111111111",
	}}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Mining.Workers != 3 || len(c2.P2P.Peers) != 1 || c2.P2P.Peers[0].Kind != KindTCP {
		t.Fatal("roundtrip lost fields")
	}
	if c2.Consensus.GenesisTime != c.Consensus.GenesisTime {
		t.Fatal("consensus params lost")
	}
}

func TestInvalidConfigsRejected(t *testing.T) {
	c := Defaults(t.TempDir())
	c.Consensus.RateBaseMicroBP = 1_100_000 // > 1% ceiling
	if err := c.Validate(); err == nil {
		t.Fatal("rate ceiling violation accepted")
	}
	c = Defaults(t.TempDir())
	c.Mining.Enabled = true
	c.Mining.Workers = 0
	if err := c.Validate(); err == nil {
		t.Fatal("zero workers accepted")
	}
	c = Defaults(t.TempDir())
	c.Mining.PayoutAddress = "not-an-address"
	c.Mining.Enabled = true
	if err := c.Validate(); err == nil {
		t.Fatal("bad payout address accepted")
	}
}

func TestConsensusParamsAdapter(t *testing.T) {
	p := consensus.Defaults()
	if p.MaxBlockSizeLimit() != int(p.MaxBlockSize) || p.MaxTxSizeLimit() != int(p.MaxTxSize) {
		t.Fatal("ParamsView adapter mismatch")
	}
}
