// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package privacy

import (
	"testing"

	"github.com/anonymcoin/anonymcoin/config"
)

func TestNormalizePeerAddresses(t *testing.T) {
	cases := []struct {
		pc    config.PeerConfig
		kind  config.PeerKind
		host  string
		port  string
		fails bool
	}{
		{config.PeerConfig{Address: "10.0.0.5:8611", Kind: config.KindTCP}, config.KindTCP, "10.0.0.5", "8611", false},
		{config.PeerConfig{Address: "abc123.onion:8611", Kind: config.KindTor}, config.KindTor, "abc123.onion", "8611", false},
		{config.PeerConfig{Address: "plain.example.com:8611", Kind: config.KindTor}, config.KindTor, "", "", true},
		{config.PeerConfig{Address: "someBase64Destination==", Kind: config.KindI2P}, config.KindI2P, "someBase64Destination==", "", false},
		{config.PeerConfig{Address: "no port", Kind: config.KindTCP}, config.KindTCP, "", "", true},
	}
	for i, c := range cases {
		kind, host, port, err := NormalizePeerAddress(c.pc)
		if c.fails {
			if err == nil {
				t.Fatalf("case %d: expected failure", i)
			}
			continue
		}
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if kind != c.kind || host != c.host || port != c.port {
			t.Fatalf("case %d: got %s/%s/%s", i, kind, host, port)
		}
	}
}

func TestValidateFingerprint(t *testing.T) {
	valid := "AN0123456789abcdef0123456789abcdef"
	if !ValidateFingerprint(valid) {
		t.Fatal("valid fingerprint rejected")
	}
	for _, bad := range []string{"", "XY0123456789abcdef0123456789abcdef", "AN123", "ANzzzz56789abcdef0123456789abcdef"} {
		if ValidateFingerprint(bad) {
			t.Fatalf("invalid fingerprint accepted: %q", bad)
		}
	}
}

func TestPolicyConstants(t *testing.T) {
	if PublicPeerDiscovery || AddressGossip {
		t.Fatal("privacy policy flags must be permanently disabled")
	}
	if !MandatoryTLS13 || !HandshakeIsPostQuantum {
		t.Fatal("mandatory protections disabled")
	}
}
