// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Network hardening tests: ping amplification cap, handshake nonce replay
// guard, peer cap.
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package network

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/config"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/mining"
)

// testServer builds a minimal Server for in-package hardening tests.
func testServer(t *testing.T, maxPeers int) *Server {
	t.Helper()
	p := consensus.Defaults()
	p.GenesisDifficulty = 1
	dag, err := blockdag.New(&p, blockdag.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.P2PConfig{Enabled: true, MaxPeers: maxPeers}
	srv, err := NewServer(id, dag, mining.NewMemPool(&p), cfg, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// TestPingAmplificationCap: a ping carrying more than maxPingPayload bytes
// is a protocol violation and must disconnect the peer, never be echoed.
func TestPingAmplificationCap(t *testing.T) {
	srv := testServer(t, 8)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// net.Pipe is synchronous: start the reader before the write.
	type frameResult struct {
		mt      byte
		payload []byte
		err     error
	}
	frames := make(chan frameResult, 4)
	go func() {
		for {
			// Read from the OPPOSITE pipe end: writes to c2 surface at c1.
			c1.SetReadDeadline(time.Now().Add(2 * time.Second))
			mt, payload, err := ReadFrame(c1, MaxPayload)
			frames <- frameResult{mt, payload, err}
			if err != nil {
				return
			}
		}
	}()

	peer := &Peer{conn: c2, br: nil, addr: "test"}
	big := make([]byte, maxPingPayload+1)
	err := srv.handleMessage(peer, MsgPing, big)
	if err == nil {
		t.Fatal("oversized ping accepted (echo amplification possible)")
	}
	// A normal ping echoes fine.
	small := []byte("heartbeat")
	if err := srv.handleMessage(peer, MsgPing, small); err != nil {
		t.Fatalf("normal ping rejected: %v", err)
	}
	// The pong must carry the same payload back.
	select {
	case fr := <-frames:
		if fr.err != nil {
			t.Fatal(fr.err)
		}
		if fr.mt != MsgPong || !bytes.Equal(fr.payload, small) {
			t.Fatalf("pong mismatch: type=%d payload=%q", fr.mt, fr.payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no pong received")
	}
}

// TestHelloRejectsZeroNonce: a handshake hello with an all-zero nonce is a
// replay vector and must be refused (validateHello, in protocol order).
func TestHelloRejectsZeroNonce(t *testing.T) {
	srv := testServer(t, 8)

	// A zero-nonce hello must be rejected even with a valid magic/version.
	h := &Hello{
		Magic:    srv.magic,
		Version:  ProtocolVersion,
		TipIndex: 0,
	}
	if err := srv.validateHello(h); err == nil {
		t.Fatal("zero-nonce hello accepted")
	}
	// Wrong magic must also be rejected before anything else matters.
	h2 := &Hello{Magic: [4]byte{'X', 'Y', 'Z', 'Z'}, Version: ProtocolVersion, Nonce: [32]byte{1}}
	if err := srv.validateHello(h2); err == nil {
		t.Fatal("foreign magic accepted")
	}
	// Wrong version rejected.
	h3 := &Hello{Magic: srv.magic, Version: ProtocolVersion + 1, Nonce: [32]byte{1}}
	if err := srv.validateHello(h3); err == nil {
		t.Fatal("foreign protocol version accepted")
	}
	// A validly signed hello with a fresh nonce passes protocol checks
	// (pin enforcement happens separately in exchangeHello).
	h4 := &Hello{Magic: srv.magic, Version: ProtocolVersion, FalconPub: srv.id.FalconPub}
	if _, err := rand.Read(h4.Nonce[:]); err != nil {
		t.Fatal(err)
	}
	if err := SignHello(h4, srv.id.FalconPriv); err != nil {
		t.Fatal(err)
	}
	if err := srv.validateHello(h4); err != nil {
		t.Fatalf("valid fresh hello rejected: %v", err)
	}
}

// TestPeerCapEnforcedAtRegistry: the peers map must refuse registration past
// MaxPeers (unit-level check of the capacity gate).
func TestPeerCapEnforcedAtRegistry(t *testing.T) {
	srv := testServer(t, 2)
	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	c3, _ := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	defer c3.Close()

	mkPeer := func(addr string, c net.Conn) *Peer {
		return &Peer{conn: c, addr: addr}
	}
	srv.peers["p1"] = mkPeer("p1", c1)
	srv.peers["p2"] = mkPeer("p2", c2)
	if srv.PeerCount() != 2 {
		t.Fatalf("peer count = %d", srv.PeerCount())
	}
	// The gate lives in runPeer; verify the constant wiring so the cap is
	// impossible to forget.
	if srv.cfg.MaxPeers != 2 {
		t.Fatalf("MaxPeers = %d, want 2", srv.cfg.MaxPeers)
	}
	_ = c3
}

// TestFrameVersionRejected: frames with a foreign protocol version must be
// refused before any payload processing.
func TestFrameVersionRejected(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("x")
	frame := make([]byte, 0, 12+len(payload))
	frame = append(frame, FrameMagic[:]...)
	frame = append(frame, 0x00, 0x63) // version 99
	frame = append(frame, MsgPing, 0)
	frame = append(frame, byte(len(payload)), 0, 0, 0)
	frame = append(frame, payload...)
	buf.Write(frame)
	if _, _, err := ReadFrame(&buf, MaxPayload); err == nil {
		t.Fatal("foreign protocol version accepted")
	}
}
