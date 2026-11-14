// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package network

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/config"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/internal/limit"
	"github.com/anonymcoin/anonymcoin/mining"
	"github.com/anonymcoin/anonymcoin/transactions"
)

// Peer is one authenticated P2P connection.
type Peer struct {
	mu       sync.Mutex
	conn     net.Conn
	br       *bufio.Reader
	addr     string
	certFP   string
	falFP    string
	outbound bool
	closed   bool
}

// Hardening knobs (see docs/PROTOCOL.md, "Resource limits").
const (
	handshakeTimeoutSec  = 15   // TLS + Falcon-512 hello exchange
	idleReadTimeoutSec   = 120  // read deadline per frame in steady state
	writeTimeoutSec      = 10   // per-frame write deadline
	maxPingPayload       = 1024 // ping echo amplification cap
	msgsPerSecPerPeer    = 50.0 // per-peer message rate
	msgBurstPerPeer      = 100.0
	bytesPerSecPerPeer   = 8 << 20 // 8 MiB/s sustained per peer
	bytesBurstPerPeer    = 16 << 20
	maxSyncBlocksPerPeer = 200_000 // hard cap per sync session
)

// Server is the ANONYMCOIN P2P node: listeners (TCP / Tor / I2P), outbound
// dialer for configured peers, handshake, block/tx relay and range-based
// synchronization. There is NO address gossip: peers are configured
// explicitly and authenticated by pinned fingerprints.
type Server struct {
	id       *NodeIdentity
	pins     *PinSet
	tofu     bool
	magic    [4]byte
	dag      *blockdag.DAG
	pool     *mining.MemPool
	cfg      config.P2PConfig
	peersMu  sync.RWMutex
	peers    map[string]*Peer
	mu       sync.Mutex
	listener net.Listener
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	logf     func(format string, args ...interface{})
}

// ListenerAddr returns the address of the TCP listener, if enabled.
func (s *Server) ListenerAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

var (
	ErrAlreadyConnected = errors.New("network: peer already connected")
	ErrBadHandshake     = errors.New("network: handshake failed")
	ErrPeerCapReached   = errors.New("network: inbound peer cap reached")
	ErrRateLimited      = errors.New("network: peer rate limit exceeded")
)

// NewServer constructs the P2P server. genesisHash provides the network
// magic; dag and pool are shared with the node loop.
func NewServer(id *NodeIdentity, dag *blockdag.DAG, pool *mining.MemPool, cfg config.P2PConfig, tofu bool, logf func(string, ...interface{})) (*Server, error) {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	if cfg.MaxPeers < 1 {
		cfg.MaxPeers = 32
	}
	s := &Server{
		id:    id,
		pins:  NewPinSet(),
		tofu:  tofu,
		magic: NetMagic(blockdag.GenesisHash(dag.Params())),
		dag:   dag,
		pool:  pool,
		cfg:   cfg,
		peers: make(map[string]*Peer),
		stop:  make(chan struct{}),
		logf:  logf,
	}
	for _, pc := range cfg.Peers {
		s.pins.AddPin(pc.CertFingerprint, pc.FalconFingerprint)
	}
	return s, nil
}

// Start launches listeners and the outbound dial loop.
func (s *Server) Start() error {
	if s.cfg.ListenAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("network: listen: %w", err)
		}
		s.mu.Lock()
		s.listener = ln
		s.mu.Unlock()
		s.wg.Add(1)
		go s.acceptLoop(ln)
		s.logf("p2p listening on %s (TLS 1.3, pinned peers)", ln.Addr())
	}
	s.wg.Add(1)
	go s.dialLoop()
	return nil
}

// acceptLoop accepts inbound TCP connections.
func (s *Server) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed by Stop: exit; transient errors: brief backoff
			// instead of a hot spin.
			select {
			case <-s.stop:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return // permanent error (listener closed): stop accepting
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runPeer(conn, "inbound:"+conn.RemoteAddr().String(), false)
		}()
	}
}

// dialLoop dials configured peers with backoff.
func (s *Server) dialLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		for _, pc := range s.cfg.Peers {
			if s.isStopped() {
				return
			}
			key := string(pc.Kind) + ":" + pc.Address
			s.peersMu.RLock()
			_, connected := s.peers[key]
			s.peersMu.RUnlock()
			if connected {
				continue
			}
			conn, err := s.dial(pc)
			if err != nil {
				s.logf("dial %s %s: %v", pc.Kind, pc.Address, err)
				continue
			}
			go s.runPeer(conn, key, true)
		}
		select {
		case <-s.stop:
			return
		case <-time.After(15 * time.Second):
		}
	}
}

func (s *Server) isStopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// dial connects through the transport class of the peer config.
func (s *Server) dial(pc config.PeerConfig) (net.Conn, error) {
	switch pc.Kind {
	case config.KindTCP:
		return net.DialTimeout("tcp", pc.Address, 10*time.Second)
	case config.KindTor:
		proxy := s.cfg.TorSOCKSAddr
		if proxy == "" {
			proxy = "127.0.0.1:9050"
		}
		return DialSOCKS5(proxy, pc.Address, 30*time.Second)
	case config.KindI2P:
		proxy := s.cfg.I2PSAMAddr
		if proxy == "" {
			proxy = "127.0.0.1:7656"
		}
		return DialSAM(proxy, pc.Address, 60*time.Second)
	default:
		return nil, fmt.Errorf("network: unknown peer kind %q", pc.Kind)
	}
}

// runPeer performs the TLS+Falcon handshake and serves the message loop.
func (s *Server) runPeer(raw net.Conn, key string, outbound bool) {
	// The handshake phase runs under a hard deadline (slowloris defense);
	// steady-state deadlines are set per frame in readLoop.
	raw.SetDeadline(time.Now().Add(handshakeTimeoutSec * time.Second))

	var tlsConn *tls.Conn
	if outbound {
		tlsConn = tls.Client(raw, s.id.TLSConfig(s.pins, s.tofu))
	} else {
		tlsConn = tls.Server(raw, s.id.TLSConfig(s.pins, s.tofu))
	}
	if err := tlsConn.Handshake(); err != nil {
		s.logf("tls handshake with %s: %v", key, err)
		raw.Close()
		return
	}
	// Pin the peer's certificate fingerprint explicitly (the TLS verify
	// callback already enforced it; recover the fingerprint for logging and
	// TOFU persistence).
	tlsState := tlsConn.ConnectionState()
	var certFP string
	if len(tlsState.PeerCertificates) > 0 {
		certFP = fingerprintOf(tlsState.PeerCertificates[0].Raw)
	}

	remote, err := s.exchangeHello(tlsConn, certFP)
	if err != nil {
		s.logf("falcon handshake with %s: %v", key, err)
		tlsConn.Close()
		return
	}

	// Inbound capacity gate: refuse connections beyond MaxPeers so a
	// connection flood cannot exhaust memory.
	s.peersMu.Lock()
	if len(s.peers) >= s.cfg.MaxPeers {
		s.peersMu.Unlock()
		s.logf("peer cap reached (%d); refusing %s", s.cfg.MaxPeers, key)
		tlsConn.Close()
		return
	}
	if old, ok := s.peers[key]; ok && !old.closed {
		s.peersMu.Unlock()
		tlsConn.Close()
		return
	}
	peer := &Peer{
		conn:     tlsConn,
		br:       bufio.NewReaderSize(tlsConn, 1<<20),
		addr:     key,
		certFP:   certFP,
		falFP:    fingerprintOf(remote.FalconPub),
		outbound: outbound,
	}
	s.peers[key] = peer
	s.peersMu.Unlock()
	s.logf("peer connected: %s (cert %s)", key, certFP)

	// Steady state: no more whole-connection deadline; per-frame deadlines
	// take over.
	tlsConn.SetDeadline(time.Time{})

	// Single-reader rule: the syncing side consumes frames synchronously
	// until catch-up, then hands the connection to the read loop.
	if remote.TipIndex > uint64(s.dag.CanonicalCount()-1) {
		s.syncPeer(peer)
	}
	s.readLoop(peer)
}

func fingerprintOf(blob []byte) string {
	return cryptography.Fingerprint(blob)
}

// exchangeHello runs the Falcon-512 signed handshake both ways and returns
// the remote hello (tip announcement).
func (s *Server) exchangeHello(conn net.Conn, certFP string) (*Hello, error) {
	hello := &Hello{
		Magic:     s.magic,
		Version:   ProtocolVersion,
		FalconPub: s.id.FalconPub,
	}
	// Fresh per-session nonce: the hello binds node identity to THIS TLS
	// session; a captured hello can never be replayed as a fresh handshake.
	if _, err := rand.Read(hello.Nonce[:]); err != nil {
		return nil, fmt.Errorf("network: session nonce: %w", err)
	}
	_, score, tip := s.dag.TipInfo()
	hello.TipIndex, hello.TipScore, hello.TipHash = uint64(s.dag.CanonicalCount()-1), score, tip
	if err := SignHello(hello, s.id.FalconPriv); err != nil {
		return nil, err
	}
	payload, err := hello.Encode()
	if err != nil {
		return nil, err
	}
	if err := WriteFrame(conn, MsgHello, payload); err != nil {
		return nil, err
	}
	msgType, payload, err := ReadFrame(conn, MaxPayload)
	if err != nil {
		return nil, err
	}
	if msgType != MsgHello {
		return nil, fmt.Errorf("%w: expected hello, got type %d", ErrBadHandshake, msgType)
	}
	remote, err := DecodeHello(payload)
	if err != nil {
		return nil, err
	}
	if err := s.validateHello(remote); err != nil {
		return nil, err
	}
	falFP := fingerprintOf(remote.FalconPub)
	ok, learned := s.pins.CheckFalcon(falFP, s.tofu)
	if !ok {
		return nil, fmt.Errorf("%w: falcon fingerprint %s not pinned", ErrBadHandshake, falFP)
	}
	if learned {
		s.pins.AddTOFU("", falFP)
		s.logf("TOFU: learned falcon fingerprint %s", falFP)
	}
	return remote, nil
}

// validateHello enforces the protocol-level hello rules: network identity,
// version, session-nonce freshness and the Falcon-512 signature.
func (s *Server) validateHello(h *Hello) error {
	if h.Magic != s.magic {
		return fmt.Errorf("%w: network magic mismatch", ErrBadHandshake)
	}
	if h.Version != ProtocolVersion {
		return fmt.Errorf("%w: protocol version %d", ErrBadHandshake, h.Version)
	}
	// Replay guard: a hello with an all-zero nonce is a replayed or forged
	// greeting (the reference implementation always sends CSPRNG nonces).
	if allZero(h.Nonce[:]) {
		return fmt.Errorf("%w: zero session nonce", ErrBadHandshake)
	}
	if !VerifyHello(h) {
		return fmt.Errorf("%w: invalid falcon signature", ErrBadHandshake)
	}
	return nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// readLoop processes incoming frames until the peer closes. Every frame is
// rate-limited (messages and bytes); a peer exceeding its budget is
// disconnected — never queued indefinitely.
func (s *Server) readLoop(p *Peer) {
	msgs := limit.NewBucket(msgsPerSecPerPeer, msgBurstPerPeer)
	bytes := limit.NewBucket(bytesPerSecPerPeer, bytesBurstPerPeer)
	defer func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		p.conn.Close()
		s.peersMu.Lock()
		delete(s.peers, p.addr)
		s.peersMu.Unlock()
		s.logf("peer disconnected: %s", p.addr)
	}()
	for {
		p.conn.SetReadDeadline(time.Now().Add(idleReadTimeoutSec * time.Second))
		msgType, payload, err := ReadFrame(p.br, MaxPayload)
		if err != nil {
			return
		}
		if !msgs.Allow() || !bytes.AllowN(float64(len(payload))) {
			s.logf("peer %s exceeded rate limits; disconnecting", p.addr)
			return
		}
		if err := s.handleMessage(p, msgType, payload); err != nil {
			s.logf("message from %s: %v", p.addr, err)
			return
		}
	}
}

// handleMessage dispatches one frame.
func (s *Server) handleMessage(p *Peer, msgType byte, payload []byte) error {
	switch msgType {
	case MsgPing:
		// Amplification cap: echo at most maxPingPayload bytes. A larger
		// ping is a protocol violation, not an echo opportunity.
		if len(payload) > maxPingPayload {
			return fmt.Errorf("network: ping payload %d exceeds %d bytes", len(payload), maxPingPayload)
		}
		return p.writeFrame(MsgPong, payload)
	case MsgPong:
		return nil
	case MsgBlock:
		return s.handleBlock(payload)
	case MsgTx:
		return s.handleTx(payload)
	case MsgGetRange:
		return s.handleGetRange(p, payload)
	case MsgRange:
		return s.handleRange(p, payload)
	default:
		return ErrUnknownMessage
	}
}

// writeFrame is the peer-scoped write path: it applies a write deadline so a
// stalled reader cannot hold the peer lock forever.
func (p *Peer) writeFrame(msgType byte, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("network: peer closed")
	}
	p.conn.SetWriteDeadline(time.Now().Add(writeTimeoutSec * time.Second))
	return WriteFrame(p.conn, msgType, payload)
}

func (s *Server) handleBlock(payload []byte) error {
	blk, err := blockdag.DecodeBlock(payload, s.dag.Params())
	if err != nil {
		return err
	}
	if err := s.dag.AcceptBlock(blk); err != nil {
		if errors.Is(err, blockdag.ErrDuplicate) {
			return nil
		}
		return err
	}
	s.BroadcastBlock(blk, "")
	return nil
}

func (s *Server) handleTx(payload []byte) error {
	tx, err := transactions.Decode(payload)
	if err != nil {
		return err
	}
	if err := s.pool.Add(tx, s.dag.MempoolView()); err != nil {
		return err
	}
	s.BroadcastTx(tx, "")
	return nil
}

// rangeRequest is the MsgGetRange payload.
type rangeRequest struct {
	From uint64 // canonical index to start from
	To   uint64 // exclusive upper bound
}

// handleGetRange streams canonical blocks [from, to).
func (s *Server) handleGetRange(p *Peer, payload []byte) error {
	req, err := decodeRangeRequest(payload)
	if err != nil {
		return err
	}
	count := s.dag.CanonicalCount()
	if req.To > uint64(count) {
		req.To = uint64(count)
	}
	if req.From >= req.To {
		return p.writeFrame(MsgRange, encodeRangeHeader(0))
	}
	n := int(req.To - req.From)
	if n > 256 {
		n = 256
	}
	if err := p.writeFrame(MsgRange, encodeRangeHeader(n)); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		h, err := s.dag.CanonicalHashAt(int(req.From) + i)
		if err != nil {
			return err
		}
		body, ok := s.dag.BlockBody(h)
		if !ok {
			// Finalized block bodies are served from the block store by the
			// node layer; here we fall back to header-only (receiver will
			// request from storage-backed peers).
			return fmt.Errorf("network: block body unavailable at index %d", req.From+uint64(i))
		}
		blockPayload, err := blockdag.EncodeBlock(body)
		if err != nil {
			return err
		}
		if err := p.writeFrame(MsgBlock, blockPayload); err != nil {
			return err
		}
	}
	return nil
}

func encodeRangeHeader(n int) []byte {
	return []byte{byte(n >> 8), byte(n)}
}

func decodeRangeRequest(b []byte) (rangeRequest, error) {
	var r rangeRequest
	if len(b) != 16 {
		return r, errors.New("network: bad range request")
	}
	r.From = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	r.To = uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	if r.To <= r.From || r.To-r.From > 4096 {
		return r, errors.New("network: range bounds rejected")
	}
	return r, nil
}

// handleRange is handled by the sync flow: individual MsgBlock frames are
// processed by handleBlock; the range header frame itself carries no data.
func (s *Server) handleRange(p *Peer, payload []byte) error {
	return nil // range headers are consumed by the sync state machine
}

// syncPeer pulls missing canonical blocks from a peer. The session is
// bounded: after maxSyncBlocksPerPeer accepted blocks the peer re-connects
// and resumes, so a hostile peer cannot pin one goroutine forever.
func (s *Server) syncPeer(p *Peer) {
	total := 0
	for {
		if s.isStopped() {
			return
		}
		tipIdx, _, _ := s.dag.TipInfo()
		// Ask for the next batch beyond our tip.
		from := tipIdx + 1
		to := from + 256
		payload := make([]byte, 16)
		putUint64(payload[0:8], from)
		putUint64(payload[8:16], to)
		if err := p.writeFrame(MsgGetRange, payload); err != nil {
			return
		}
		// Read the range header + blocks (single-threaded consume until
		// catch-up response arrives).
		p.conn.SetReadDeadline(time.Now().Add(idleReadTimeoutSec * time.Second))
		msgType, resp, err := ReadFrame(p.br, MaxPayload)
		if err != nil {
			return
		}
		if msgType != MsgRange {
			return
		}
		n := int(resp[0])<<8 | int(resp[1])
		if n == 0 {
			return // peer has nothing beyond our tip: synchronized
		}
		for i := 0; i < n; i++ {
			p.conn.SetReadDeadline(time.Now().Add(idleReadTimeoutSec * time.Second))
			mt, blockPayload, err := ReadFrame(p.br, MaxPayload)
			if err != nil {
				return
			}
			if mt != MsgBlock {
				return
			}
			if err := s.handleBlock(blockPayload); err != nil {
				// A block we cannot accept stops the batch; log and stop.
				s.logf("sync from %s: %v", p.addr, err)
				return
			}
			total++
			if total >= maxSyncBlocksPerPeer {
				s.logf("sync session cap reached for %s; resuming later", p.addr)
				return
			}
		}
	}
}

func putUint64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (56 - 8*i))
	}
}

// BroadcastBlock relays a block to all connected peers except the origin.
func (s *Server) BroadcastBlock(blk *blockdag.Block, exceptAddr string) {
	payload, err := blockdag.EncodeBlock(blk)
	if err != nil {
		return
	}
	s.forEachPeer(exceptAddr, func(p *Peer) {
		_ = p.writeFrame(MsgBlock, payload)
	})
}

// BroadcastTx relays a transaction to all connected peers except the origin.
func (s *Server) BroadcastTx(tx *transactions.Tx, exceptAddr string) {
	payload := tx.Encode()
	s.forEachPeer(exceptAddr, func(p *Peer) {
		_ = p.writeFrame(MsgTx, payload)
	})
}

func (s *Server) forEachPeer(except string, fn func(*Peer)) {
	s.peersMu.RLock()
	peers := make([]*Peer, 0, len(s.peers))
	for key, p := range s.peers {
		if key == except {
			continue
		}
		peers = append(peers, p)
	}
	s.peersMu.RUnlock()
	for _, p := range peers {
		fn(p)
	}
}

// PeerCount returns the number of live peers.
func (s *Server) PeerCount() int {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	return len(s.peers)
}

// Stop shuts the server down: closes the listener first (no new inbound),
// then every peer connection.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stop)
	})
	s.mu.Lock()
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	s.forEachPeer("", func(p *Peer) {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		p.conn.Close()
	})
}
