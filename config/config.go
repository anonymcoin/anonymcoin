// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package config loads, validates and saves the ANONYMCOIN node
// configuration (config.json). All consensus parameters are embedded so that
// operators and tests can run alternative parameter sets; nodes with
// different consensus parameters will not converge.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
)

// PeerKind is the transport class of a configured peer.
type PeerKind string

const (
	KindTCP PeerKind = "tcp" // plain TCP with TLS 1.3
	KindTor PeerKind = "tor" // Tor onion service via SOCKS5
	KindI2P PeerKind = "i2p" // I2P eepsite via SAM v3
)

// PeerConfig is one privately configured peer. ANONYMCOIN has no public peer
// directory: peers are configured explicitly and authenticated by pinned
// fingerprints (TLS certificate fingerprint and Falcon-512 public key
// fingerprint). With TrustOnFirstUse=true an unset fingerprint pair is
// learned on first connection and persisted by the caller.
type PeerConfig struct {
	Address           string   `json:"address"` // host:port (tcp) | host.onion:port (tor) | dest (i2p)
	Kind              PeerKind `json:"kind"`    // tcp | tor | i2p
	CertFingerprint   string   `json:"cert_fingerprint,omitempty"`
	FalconFingerprint string   `json:"falcon_fingerprint,omitempty"`
	TrustOnFirstUse   bool     `json:"trust_on_first_use,omitempty"`
	DialOnly          bool     `json:"dial_only,omitempty"`
}

// P2PConfig configures the private P2P layer.
type P2PConfig struct {
	Enabled         bool         `json:"enabled"`
	ListenAddr      string       `json:"listen_addr"` // "" disables inbound TCP
	Port            int          `json:"port"`
	Peers           []PeerConfig `json:"peers"`
	MaxPeers        int          `json:"max_peers"`
	TorSOCKSAddr    string       `json:"tor_socks_addr"` // e.g. 127.0.0.1:9050
	I2PSAMAddr      string       `json:"i2p_sam_addr"`   // e.g. 127.0.0.1:7656
	NoAddressGossip bool         `json:"no_address_gossip"`
}

// RPCConfig configures the local JSON-over-TCP control interface.
type RPCConfig struct {
	Enabled    bool   `json:"enabled"`
	ListenAddr string `json:"listen_addr"`
	Token      string `json:"token"`
}

// MiningConfig configures the CPU miner.
type MiningConfig struct {
	Enabled       bool   `json:"enabled"`
	Workers       int    `json:"workers"`
	PayoutAddress string `json:"payout_address"`
}

// Config is the full node configuration.
type Config struct {
	DataDir   string           `json:"data_dir"`
	P2P       P2PConfig        `json:"p2p"`
	RPC       RPCConfig        `json:"rpc"`
	Mining    MiningConfig     `json:"mining"`
	Consensus consensus.Params `json:"consensus"`
	LogLevel  string           `json:"log_level"`
}

// Defaults returns the default configuration for the given data directory.
func Defaults(dataDir string) Config {
	return Config{
		DataDir: dataDir,
		P2P: P2PConfig{
			Enabled:         true,
			ListenAddr:      "",
			Port:            8611,
			Peers:           nil,
			MaxPeers:        32,
			TorSOCKSAddr:    "127.0.0.1:9050",
			I2PSAMAddr:      "127.0.0.1:7656",
			NoAddressGossip: true,
		},
		RPC: RPCConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:8612",
			Token:      "",
		},
		Mining: MiningConfig{
			Enabled: false,
			Workers: 1,
		},
		Consensus: consensus.Defaults(),
		LogLevel:  "info",
	}
}

// Load reads and validates a configuration file.
func Load(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("config: read: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("config: parse: %w", err)
	}
	// A config with no consensus block at all inherits the ANONYMCOIN
	// mainnet defaults. Partial consensus blocks validate strictly so that
	// accidental omissions cannot silently change the network.
	if c.Consensus.BlockIntervalSec == 0 && c.Consensus.GenesisTime == 0 {
		c.Consensus = consensus.Defaults()
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

// Save writes the configuration as indented JSON.
func Save(path string, c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Validate checks the configuration for contradictions.
func (c *Config) Validate() error {
	if err := c.Consensus.Validate(); err != nil {
		return fmt.Errorf("config: consensus params: %w", err)
	}
	if c.P2P.Enabled && c.P2P.MaxPeers < 1 {
		return errors.New("config: p2p.max_peers must be at least 1")
	}
	if c.Mining.Enabled && c.Mining.Workers < 1 {
		return errors.New("config: mining.workers must be at least 1")
	}
	if c.Mining.Enabled && c.Mining.PayoutAddress != "" &&
		!validAddress(c.Mining.PayoutAddress) {
		return errors.New("config: mining.payout_address is not a valid address")
	}
	for _, p := range c.P2P.Peers {
		switch p.Kind {
		case KindTCP, KindTor, KindI2P:
		case "":
			return fmt.Errorf("config: peer %q missing kind", p.Address)
		default:
			return fmt.Errorf("config: peer %q unknown kind %q", p.Address, p.Kind)
		}
	}
	return nil
}

func validAddress(a string) bool {
	_, err := decodeAddr(a)
	return err == nil
}

func decodeAddr(a string) ([20]byte, error) {
	return cryptography.AddressToPubKeyHash(a)
}
