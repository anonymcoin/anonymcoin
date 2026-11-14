// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package network

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/anonymcoin/anonymcoin/cryptography"
)

// NodeIdentity is a node's fixed cryptographic identity: a long-lived
// Ed25519 key pair materialized as a self-signed TLS 1.3 certificate, plus a
// Falcon-512 key pair for the post-quantum handshake signature. Both keys
// are persisted unencrypted in the data directory (they identify the NODE,
// not funds; wallet keys are separately encrypted) with 0600 permissions.
type NodeIdentity struct {
	TLSKey     ed25519.PrivateKey
	TLSCertDER []byte
	FalconPub  []byte
	FalconPriv []byte
}

// CertFingerprint returns the pinned TLS certificate fingerprint.
func (id *NodeIdentity) CertFingerprint() string {
	return cryptography.Fingerprint(id.TLSCertDER)
}

// FalconFingerprint returns the pinned Falcon-512 public key fingerprint.
func (id *NodeIdentity) FalconFingerprint() string {
	return cryptography.Fingerprint(id.FalconPub)
}

type identityFile struct {
	TLSKeyPEM  string `json:"tls_key_pem"`
	TLSCertPEM string `json:"tls_cert_pem"`
	FalconPub  string `json:"falcon_pub_b64"`
	FalconPriv string `json:"falcon_priv_b64"`
	CreatedAt  int64  `json:"created_at"`
}

// LoadOrCreateIdentity loads the node identity from datadir/identity.json
// or deterministically creates and persists a new one.
func LoadOrCreateIdentity(datadir string) (*NodeIdentity, error) {
	path := filepath.Join(datadir, "identity.json")
	if b, err := os.ReadFile(path); err == nil {
		var f identityFile
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("network: identity parse: %w", err)
		}
		return parseIdentity(f)
	}
	// Generate.
	tlsPub, tlsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	certDER, err := selfSignedCert(tlsPub, tlsPriv)
	if err != nil {
		return nil, err
	}
	fPub, fPriv, err := cryptography.FalconGenerate()
	if err != nil {
		return nil, fmt.Errorf("network: falcon keygen: %w", err)
	}
	id := &NodeIdentity{
		TLSKey:     tlsPriv,
		TLSCertDER: certDER,
		FalconPub:  fPub,
		FalconPriv: fPriv,
	}
	f := identityFile{
		TLSKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsPriv})),
		TLSCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		FalconPub:  base64.StdEncoding.EncodeToString(fPub),
		FalconPriv: base64.StdEncoding.EncodeToString(fPriv),
		CreatedAt:  time.Now().Unix(),
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := os.MkdirAll(datadir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("network: identity save: %w", err)
	}
	_ = tlsPub
	return id, nil
}

func parseIdentity(f identityFile) (*NodeIdentity, error) {
	keyBlock, _ := pem.Decode([]byte(f.TLSKeyPEM))
	certBlock, _ := pem.Decode([]byte(f.TLSCertPEM))
	if keyBlock == nil || certBlock == nil {
		return nil, errors.New("network: identity PEM invalid")
	}
	fPub, err := base64.StdEncoding.DecodeString(f.FalconPub)
	if err != nil {
		return nil, err
	}
	fPriv, err := base64.StdEncoding.DecodeString(f.FalconPriv)
	if err != nil {
		return nil, err
	}
	return &NodeIdentity{
		TLSKey:     ed25519.PrivateKey(keyBlock.Bytes),
		TLSCertDER: certBlock.Bytes,
		FalconPub:  fPub,
		FalconPriv: fPriv,
	}, nil
}

func selfSignedCert(pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"ANONYMCOIN"},
			CommonName:   "anonymcoin-node",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"anonymcoin"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// PinSet is the set of accepted peer key fingerprints. TOFU entries are
// learned on first contact and recorded by the caller.
type PinSet struct {
	mu       sync.RWMutex
	cert     map[string]struct{}
	falcon   map[string]struct{}
	tofuCert map[string]struct{}
	tofuFal  map[string]struct{}
}

// NewPinSet builds an empty pin set.
func NewPinSet() *PinSet {
	return &PinSet{
		cert:     make(map[string]struct{}),
		falcon:   make(map[string]struct{}),
		tofuCert: make(map[string]struct{}),
		tofuFal:  make(map[string]struct{}),
	}
}

// AddPin registers a strictly pinned pair of fingerprints.
func (ps *PinSet) AddPin(certFP, falconFP string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if certFP != "" {
		ps.cert[certFP] = struct{}{}
	}
	if falconFP != "" {
		ps.falcon[falconFP] = struct{}{}
	}
}

// AddTOFU registers a trust-on-first-use fingerprint (weaker: logged by the
// caller the first time it is seen).
func (ps *PinSet) AddTOFU(certFP, falconFP string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if certFP != "" {
		ps.tofuCert[certFP] = struct{}{}
	}
	if falconFP != "" {
		ps.tofuFal[falconFP] = struct{}{}
	}
}

// CheckCert accepts a certificate fingerprint if it is pinned, TOFU-known,
// or TOFU-eligible (returns learned=true so the caller can persist it).
func (ps *PinSet) CheckCert(fp string, tofu bool) (ok, learned bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if _, ok := ps.cert[fp]; ok {
		return true, false
	}
	if _, ok := ps.tofuCert[fp]; ok {
		return true, false
	}
	if tofu {
		return true, true
	}
	return false, false
}

// CheckFalcon mirrors CheckCert for Falcon-512 key fingerprints.
func (ps *PinSet) CheckFalcon(fp string, tofu bool) (ok, learned bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if _, ok := ps.falcon[fp]; ok {
		return true, false
	}
	if _, ok := ps.tofuFal[fp]; ok {
		return true, false
	}
	if tofu {
		return true, true
	}
	return false, false
}

// TLSConfig builds the pinned TLS 1.3 configuration. Both sides demand a
// client certificate (mutual, self-signed, pinned) and both verify the peer
// certificate against the pin set. VerifyPeerCertificate runs after the
// handshake with the raw peer certs.
func (id *NodeIdentity) TLSConfig(ps *PinSet, tofu bool) *tls.Config {
	cert := tls.Certificate{
		Certificate: [][]byte{id.TLSCertDER},
		PrivateKey:  id.TLSKey,
	}
	verify := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("network: peer presented no certificate")
		}
		fp := cryptography.Fingerprint(rawCerts[0])
		ok, learned := ps.CheckCert(fp, tofu)
		if !ok {
			return fmt.Errorf("network: peer certificate fingerprint %s is not pinned", fp)
		}
		if learned {
			ps.AddTOFU(fp, "")
		}
		return nil
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.3 only — fixed, modern ciphersuites, no negotiation downward.
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAnyClientCert,
		ClientCAs:  nil,
		RootCAs:    nil,
		ServerName: "anonymcoin",
		NextProtos: []string{"anonymcoin/1"},
		// The pin set performs verification; standard chain validation is
		// deliberately bypassed because the network uses self-signed,
		// fingerprint-pinned identities.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verify,
	}
}
