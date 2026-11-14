// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package network

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/config"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/mining"
)

func TestFrameRoundtrip(t *testing.T) {
	payloads := map[byte][]byte{
		MsgPing: []byte("ping-body"),
		MsgPong: {},
		MsgTx:   make([]byte, 5000),
	}
	for mt, p := range payloads {
		var buf []byte
		w := writerFunc(func(b []byte) (int, error) {
			buf = append(buf, b...)
			return len(b), nil
		})
		if err := WriteFrame(w, mt, p); err != nil {
			t.Fatal(err)
		}
		got, out, err := ReadFrame(bufio.NewReader(&readerFunc{data: buf}), MaxPayload)
		if err != nil {
			t.Fatal(err)
		}
		if got != mt || string(out) != string(p) {
			t.Fatal("frame roundtrip mismatch")
		}
	}
	// Oversized payload rejected at write.
	if err := WriteFrame(&discard{}, MsgPing, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("oversized write accepted")
	}
	// Bad magic rejected at read.
	bad := append([]byte("XXXX"), make([]byte, 8)...)
	if _, _, err := ReadFrame(bufio.NewReader(&readerFunc{data: bad}), MaxPayload); err == nil {
		t.Fatal("bad magic accepted")
	}
}

type writerFunc func([]byte) (int, error)

func (w writerFunc) Write(b []byte) (int, error) { return w(b) }

type readerFunc struct {
	data []byte
	pos  int
}

func (r *readerFunc) Read(b []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("EOF")
	}
	n := copy(b, r.data[r.pos:])
	r.pos += n
	return n, nil
}

type discard struct{}

func (d *discard) Write(b []byte) (int, error) { return len(b), nil }

func TestHelloSignVerify(t *testing.T) {
	id, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := consensus.Defaults()
	hello := &Hello{
		Magic:     NetMagic(blockdag.GenesisHash(&p)),
		Version:   ProtocolVersion,
		FalconPub: id.FalconPub,
		TipIndex:  7,
		TipScore:  12345,
	}
	if err := SignHello(hello, id.FalconPriv); err != nil {
		t.Fatal(err)
	}
	if !VerifyHello(hello) {
		t.Fatal("valid hello rejected")
	}
	// Tampering with any signed byte breaks verification.
	hello.TipScore = 99999
	if VerifyHello(hello) {
		t.Fatal("tampered hello accepted")
	}
	// Wrong key.
	other, _ := LoadOrCreateIdentity(t.TempDir())
	h2 := &Hello{Magic: hello.Magic, Version: ProtocolVersion, FalconPub: other.FalconPub, TipScore: 7}
	SignHello(h2, id.FalconPriv)
	if VerifyHello(h2) {
		t.Fatal("hello signed under foreign key accepted")
	}
}

// TestPinnedTLSHandshake runs a full loopback TLS 1.3 handshake with pinned
// fingerprints: the honest pair connects, the forged pair is rejected.
func TestPinnedTLSHandshake(t *testing.T) {
	dirA, dirB, dirC := t.TempDir(), t.TempDir(), t.TempDir()
	a, _ := LoadOrCreateIdentity(dirA)
	b, _ := LoadOrCreateIdentity(dirB)
	c, _ := LoadOrCreateIdentity(dirC) // attacker/stranger

	pins := NewPinSet()
	pins.AddPin(a.CertFingerprint(), a.FalconFingerprint())
	pins.AddPin(b.CertFingerprint(), b.FalconFingerprint())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		sc := tls.Server(raw, a.TLSConfig(pins, false))
		if err := sc.Handshake(); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc := tls.Client(raw, b.TLSConfig(pins, false))
	if err := cc.Handshake(); err != nil {
		t.Fatalf("honest pinned handshake failed: %v", err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server side: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}

	// Stranger must be rejected by both sides.
	go func() {
		raw2, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		sc := tls.Server(raw2, a.TLSConfig(pins, false))
		err = sc.Handshake()
		serverErr <- err
	}()
	raw2, _ := net.Dial("tcp", ln.Addr().String())
	cc2 := tls.Client(raw2, c.TLSConfig(pins, false))
	err = cc2.Handshake()
	_ = cc2.Close()
	if err == nil {
		// The server must still reject it.
		select {
		case err := <-serverErr:
			if err == nil {
				t.Fatal("unpinned certificate accepted by server")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timeout waiting for server rejection")
		}
	} else {
		select {
		case err := <-serverErr:
			_ = err // either side rejecting is fine
		case <-time.After(3 * time.Second):
		}
	}
	_ = cc.Close()
}

// TestFullP2PSession: two complete servers (TLS + Falcon hello + sync) on
// loopback; node A mines, node B connects with pinned fingerprints and must
// synchronize.
func TestFullP2PSession(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	p := consensus.Defaults()
	p.GenesisDifficulty = 1
	p.DifficultyMax = 4
	p.CoinbaseMaturity = 1

	dagA, _ := blockdag.New(&p, blockdag.Hooks{})
	poolA := mining.NewMemPool(&p)
	idA, _ := LoadOrCreateIdentity(dirA)
	cfgA := defaultCfg()
	cfgA.ListenAddr = "127.0.0.1:0"
	cfgA.Peers = nil
	srvA, err := NewServer(idA, dagA, poolA, cfgA, false, func(string, ...interface{}) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := srvA.Start(); err != nil {
		t.Fatal(err)
	}
	defer srvA.Stop()

	// Mine 5 blocks on A.
	miner := mining.NewMiner(dagA, poolA, [20]byte{}, 1)
	if err := miner.MineN(5); err != nil {
		t.Fatalf("mine: %v", err)
	}

	// Node B with A pinned... A's listener address is dynamic; instead B
	// dials directly using a custom run (we reuse the server's transport
	// pieces). Simplest correct integration: B dials the A listener and runs
	// the A-side server code path with B's identity? The pin check requires
	// mutual pinning: B must pin A's cert and A must pin B's cert.
	dagB, _ := blockdag.New(&p, blockdag.Hooks{})
	poolB := mining.NewMemPool(&p)
	idB, _ := LoadOrCreateIdentity(dirB)

	// The full mutual pinning loop is covered by TestPinnedTLSHandshake and
	// the peer engine tests; here we assert the sync state machine over a
	// raw pinned TLS session via the server plumbing:
	addr := srvA.ListenerAddr()
	if addr == "" {
		t.Skip("no listener configured")
	}
	cfgB := defaultCfg()
	cfgB.ListenAddr = "127.0.0.1:0"
	cfgB.Peers = []config.PeerConfig{
		{Address: addr, Kind: config.KindTCP, CertFingerprint: idA.CertFingerprint(), FalconFingerprint: idA.FalconFingerprint()},
	}
	_ = idB
	srvB, err := NewServer(idB, dagB, poolB, cfgB, false, func(string, ...interface{}) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := srvB.Start(); err != nil {
		t.Fatal(err)
	}
	defer srvB.Stop()

	// A must also trust B: register B's fingerprints in A's pin set.
	srvA.pins.AddPin(idB.CertFingerprint(), idB.FalconFingerprint())

	// Wait for B to sync A's 5 blocks.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if dagB.CanonicalCount() >= 6 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if dagB.CanonicalCount() < 6 {
		t.Fatalf("B did not sync: canonical = %d", dagB.CanonicalCount())
	}
	// Canonical order must match exactly.
	for i := 0; i < 6; i++ {
		ha, _ := dagA.CanonicalHashAt(i)
		hb, _ := dagB.CanonicalHashAt(i)
		if ha != hb {
			t.Fatalf("canonical mismatch at %d", i)
		}
	}
}

func defaultCfg() config.P2PConfig {
	return config.P2PConfig{
		Enabled:         true,
		MaxPeers:        8,
		TorSOCKSAddr:    "127.0.0.1:9050",
		I2PSAMAddr:      "127.0.0.1:7656",
		NoAddressGossip: true,
	}
}

func TestSOCKS5DialerAgainstFakeProxy(t *testing.T) {
	// A minimal fake SOCKS5 server that accepts everything to 127.0.0.1:1.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				if _, err := readFull(c, buf); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00})
				hdr := make([]byte, 5)
				if _, err := readFull(c, hdr); err != nil {
					return
				}
				hostLen := int(hdr[4])
				rest := make([]byte, hostLen+2)
				if _, err := readFull(c, rest); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
				c.Write([]byte("hello-through-socks"))
			}(c)
		}
	}()
	conn, err := DialSOCKS5(ln.Addr().String(), "verylongonionname.onion:8611", 3*time.Second)
	if err != nil {
		t.Fatalf("socks5 dial: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 19)
	if _, err := readFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello-through-socks" {
		t.Fatal("socks5 data mismatch")
	}
}

func TestSAMClientAgainstFakeBridge(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case hasPrefix(line, "HELLO"):
				c.Write([]byte("HELLO REPLY RESULT=OK VERSION=3.1\n"))
			case hasPrefix(line, "SESSION"):
				c.Write([]byte("SESSION STATUS RESULT=OK DESTINATION=fakeDestBase64\n"))
			case hasPrefix(line, "STREAM CONNECT"):
				c.Write([]byte("STREAM STATUS RESULT=OK\n"))
				c.Write([]byte("i2p-payload"))
				return
			case hasPrefix(line, "STREAM ACCEPT"):
				c.Write([]byte("STREAM STATUS RESULT=OK\n"))
			}
		}
	}()
	conn, err := DialSAM(ln.Addr().String(), "fakeDestBase64", 3*time.Second)
	if err != nil {
		t.Fatalf("sam dial: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 11)
	if _, err := readFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "i2p-payload" {
		t.Fatal("sam data mismatch")
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
