// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func parsePort(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("socks5: bad port %q", s)
	}
	return uint16(v), nil
}

// Minimal SOCKS5 client (RFC 1928, no-auth) used to reach Tor onion
// services. Tor resolves .onion hostnames at the proxy, so the target is
// always sent as a domain name.
func DialSOCKS5(proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: target: %w", err)
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("socks5: proxy dial: %w", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetDeadline(time.Now().Add(timeout))
	}
	// Greeting: version 5, no-auth only.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: greeting: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, errors.New("socks5: proxy refused no-auth method")
	}
	// CONNECT with domain name.
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, host...)
	pu, perr := parsePort(port)
	if perr != nil {
		conn.Close()
		return nil, perr
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], pu)
	req = append(req, p[:]...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: connect failed with code %d", reply[1])
	}
	// Skip bound address/port per reply address type.
	switch reply[3] {
	case 0x01:
		skip := make([]byte, 6)
		if _, err := io.ReadFull(conn, skip); err != nil {
			conn.Close()
			return nil, err
		}
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			conn.Close()
			return nil, err
		}
		skip := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			conn.Close()
			return nil, err
		}
	case 0x04:
		skip := make([]byte, 18)
		if _, err := io.ReadFull(conn, skip); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetDeadline(time.Time{})
	}
	return conn, nil
}
