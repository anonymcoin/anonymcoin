// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package privacy documents and enforces the privacy policy of the ANONYMCOIN
// P2P layer: no public peer directory, no address gossip, explicit peer
// configuration with pinned identities, and optional onion/eepsite
// transports. The code in this package validates peer addresses and
// fingerprints and exposes the policy constants referenced by the docs.
package privacy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anonymcoin/anonymcoin/config"
	"github.com/anonymcoin/anonymcoin/cryptography"
)

// Policy constants. They are enforced by the network package (no peers
// message exists on the wire at all), collected here for auditability.
const (
	// PublicPeerDiscovery is permanently disabled: there is no DHT, no
	// seed-node registry, no DNS seeds.
	PublicPeerDiscovery = false
	// AddressGossip is permanently disabled: nodes never exchange peer
	// lists, so a compromised peer cannot enumerate the network.
	AddressGossip = false
	// MandatoryTLS13: every connection is TLS 1.3 with pinned keys.
	MandatoryTLS13 = true
	// HandshakeIsPostQuantum: the handshake is signed with Falcon-512.
	HandshakeIsPostQuantum = true
)

// NormalizePeerAddress parses a configured peer address into its transport
// class and connection parameters.
func NormalizePeerAddress(pc config.PeerConfig) (kind config.PeerKind, host, port string, err error) {
	switch pc.Kind {
	case config.KindTCP:
		host, port, err = splitHostPort(pc.Address)
		return config.KindTCP, host, port, err
	case config.KindTor:
		// Format: <name>.onion:<port>
		host, port, err = splitHostPort(pc.Address)
		if err == nil && !strings.HasSuffix(host, ".onion") {
			err = errors.New("privacy: tor peer address must end in .onion")
		}
		return config.KindTor, host, port, err
	case config.KindI2P:
		// Format: base64 destination (no port; the SAM bridge routes it).
		if pc.Address == "" {
			return config.KindI2P, "", "", errors.New("privacy: i2p peer address empty")
		}
		if strings.ContainsAny(pc.Address, " \t\n") {
			return config.KindI2P, "", "", errors.New("privacy: i2p destination must be one base64 token")
		}
		return config.KindI2P, pc.Address, "", nil
	default:
		return pc.Kind, "", "", fmt.Errorf("privacy: unknown peer kind %q", pc.Kind)
	}
}

func splitHostPort(addr string) (string, string, error) {
	idx := strings.LastIndex(addr, ":")
	if idx <= 0 || idx == len(addr)-1 {
		return "", "", fmt.Errorf("privacy: address %q needs host:port", addr)
	}
	return addr[:idx], addr[idx+1:], nil
}

// ValidateFingerprint checks a fingerprint string's shape (AN + 32 hex chars).
func ValidateFingerprint(fp string) bool {
	if len(fp) != 34 || !strings.HasPrefix(fp, "AN") {
		return false
	}
	for _, c := range fp[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Describe returns the one-paragraph privacy posture of the node, used by
// the RPC getinfo output and the docs.
func Describe() string {
	return "ANONYMCOIN private networking: no public peer directory, no address " +
		"gossip, explicitly configured peers, TLS 1.3 with pinned Ed25519 node " +
		"certificates, Falcon-512 (FN-DSA-512, FIPS 206) post-quantum handshake " +
		"signatures, optional Tor onion and I2P eepsite transports via local " +
		"SOCKS5/SAM bridges. Fingerprints use BLAKE2b-256 truncated to 16 bytes " +
		"(" + cryptography.Fingerprint([]byte("anonymcoin"))[:4] + "...)."
}
