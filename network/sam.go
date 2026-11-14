// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package network

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Minimal I2P SAM v3 client (geti2p.net SAM spec) for eepsite transport.
// A session is created per connection pool; streams are plain TCP after the
// SAM handshake.
type SAMConn struct {
	sam     string
	timeout time.Duration
	conn    net.Conn
	br      *bufio.Reader
}

// samStream is the post-handshake data path: any bytes already buffered by
// the protocol reader are drained before touching the raw connection.
type samStream struct {
	net.Conn
	br *bufio.Reader
}

func (s *samStream) Read(b []byte) (int, error) {
	if n := s.br.Buffered(); n > 0 {
		return s.br.Read(b)
	}
	return s.Conn.Read(b)
}

// DialSAM opens a TCP stream to an I2P destination through a SAM bridge.
// destination is the base64 I2P destination (or "TRANSLATE" names are not
// supported — ANONYMCOIN uses raw destinations only).
func DialSAM(samAddr, destination string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", samAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("sam: dial: %w", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetDeadline(time.Now().Add(timeout))
	}
	s := &SAMConn{sam: samAddr, timeout: timeout, conn: conn, br: bufio.NewReader(conn)}
	if err := s.hello(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := s.createSession(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := s.connect(destination); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &samStream{Conn: conn, br: s.br}, nil
}

func (s *SAMConn) hello() error {
	if _, err := s.conn.Write([]byte("HELLO VERSION MIN 3.0 MAX 3.1\n")); err != nil {
		return err
	}
	line, err := s.br.ReadString('\n')
	if err != nil {
		return err
	}
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "HELLO" || f[1] != "REPLY" || f[2] != "RESULT=OK" {
		return fmt.Errorf("sam: hello refused: %s", strings.TrimSpace(line))
	}
	return nil
}

func (s *SAMConn) createSession() error {
	// TRANSIENT destination: fresh identity per session, nothing persistent
	// to leak. Session id is fixed per connection (one session per conn).
	cmd := "SESSION CREATE STYLE=STREAM ID=anon SESSION DESTINATION=TRANSIENT\n"
	if _, err := s.conn.Write([]byte(cmd)); err != nil {
		return err
	}
	line, err := s.br.ReadString('\n')
	if err != nil {
		return err
	}
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "SESSION" || f[1] != "STATUS" || f[2] != "RESULT=OK" {
		return fmt.Errorf("sam: session refused: %s", strings.TrimSpace(line))
	}
	return nil
}

func (s *SAMConn) connect(destination string) error {
	cmd := fmt.Sprintf("STREAM CONNECT ID=anon DESTINATION=%s SILENT=false\n", destination)
	if _, err := s.conn.Write([]byte(cmd)); err != nil {
		return err
	}
	line, err := s.br.ReadString('\n')
	if err != nil {
		return err
	}
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "STREAM" || f[1] != "STATUS" || f[2] != "RESULT=OK" {
		return fmt.Errorf("sam: connect refused: %s", strings.TrimSpace(line))
	}
	return nil
}

// SAMAccept listens for inbound I2P streams: it creates a session with a
// fresh transient destination and returns (conn, destinationBase64, nil) for
// each accepted stream. Callers loop over it; every call yields a new
// transient destination advertised by the operator out of band.
func SAMAccept(samAddr string, timeout time.Duration) (net.Conn, string, error) {
	conn, err := net.DialTimeout("tcp", samAddr, timeout)
	if err != nil {
		return nil, "", fmt.Errorf("sam: dial: %w", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetDeadline(time.Now().Add(timeout))
	}
	s := &SAMConn{sam: samAddr, timeout: timeout, conn: conn, br: bufio.NewReader(conn)}
	if err := s.hello(); err != nil {
		conn.Close()
		return nil, "", err
	}
	if _, err := s.conn.Write([]byte("SESSION CREATE STYLE=STREAM ID=anon SESSION DESTINATION=TRANSIENT i2cp.options.inbound.quantity=1 i2cp.options.outbound.quantity=1\n")); err != nil {
		conn.Close()
		return nil, "", err
	}
	line, err := s.br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "SESSION" || f[1] != "STATUS" || f[2] != "RESULT=OK" {
		conn.Close()
		return nil, "", fmt.Errorf("sam: session refused: %s", strings.TrimSpace(line))
	}
	// The SESSION STATUS reply carries our destination: DESTINATION=<b64>
	var dest string
	for _, field := range f {
		if strings.HasPrefix(field, "DESTINATION=") {
			dest = strings.TrimPrefix(field, "DESTINATION=")
		}
	}
	if dest == "" {
		conn.Close()
		return nil, "", errors.New("sam: session reply missing destination")
	}
	if _, err := s.conn.Write([]byte("STREAM ACCEPT ID=anon SILENT=false\n")); err != nil {
		conn.Close()
		return nil, "", err
	}
	line, err = s.br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	f = strings.Fields(line)
	if len(f) < 3 || f[0] != "STREAM" || f[1] != "STATUS" || f[2] != "RESULT=OK" {
		conn.Close()
		return nil, "", fmt.Errorf("sam: accept refused: %s", strings.TrimSpace(line))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, dest, nil
}
