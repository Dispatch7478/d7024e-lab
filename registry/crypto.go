package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var (
	ErrSignatureVerificationFailed = errors.New("signature verification failed")
	ErrInvalidEncoding             = errors.New("invalid key or signature encoding")
)

// DomainKeyPair represents the Ed25519 key pair associated with a domain identity.
type DomainKeyPair struct {
	Domain     string             `json:"domain"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
	CreatedAt  time.Time          `json:"created_at"`
}

// GenerateDomainKeyPair creates a new random Ed25519 key pair for the given domain.
func GenerateDomainKeyPair(domain string) (*DomainKeyPair, error) {
	norm := NormalizeDomain(domain)
	if !IsValidDomain(norm) {
		return nil, ErrInvalidDomain
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DomainKeyPair{Domain: norm, PublicKey: pub, PrivateKey: priv, CreatedAt: time.Now().UTC()}, nil
}

// GenerateKeyPair generates a cryptographically secure random Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign signs data using an Ed25519 private key.
func Sign(priv ed25519.PrivateKey, data []byte) ([]byte, error) {
	return ed25519.Sign(priv, data), nil
}

// Verify verifies an Ed25519 signature against data and public key.
func Verify(pub ed25519.PublicKey, data, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, data, sig) {
		return ErrSignatureVerificationFailed
	}
	return nil
}

func (dkp *DomainKeyPair) Sign(msg []byte) ([]byte, error) {
	if dkp == nil {
		return nil, errors.New("nil key pair")
	}
	return Sign(dkp.PrivateKey, msg)
}

func (dkp *DomainKeyPair) Verify(msg, sig []byte) error {
	if dkp == nil {
		return errors.New("nil key pair")
	}
	return Verify(dkp.PublicKey, msg, sig)
}

func (dkp *DomainKeyPair) PublicKeyHex() string {
	if dkp == nil {
		return ""
	}
	return EncodePublicKeyHex(dkp.PublicKey)
}
func (dkp *DomainKeyPair) DNSTXTRecord() string {
	if dkp == nil {
		return ""
	}
	return FormatDNSTXTRecord(dkp.PublicKey)
}

func cleanHex(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "\"'")
	s = strings.TrimPrefix(s, "0x")
	return strings.TrimPrefix(s, "0X")
}

func EncodePublicKeyHex(pub ed25519.PublicKey) string { return hex.EncodeToString(pub) }
func DecodePublicKeyHex(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(cleanHex(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalidEncoding
	}
	return ed25519.PublicKey(b), nil
}

func EncodePrivateKeyHex(priv ed25519.PrivateKey) string { return hex.EncodeToString(priv) }
func DecodePrivateKeyHex(s string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(cleanHex(s))
	if err != nil || (len(b) != ed25519.PrivateKeySize && len(b) != ed25519.SeedSize) {
		return nil, ErrInvalidEncoding
	}
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), nil
	}
	return ed25519.PrivateKey(b), nil
}

func EncodeSignatureHex(sig []byte) string { return hex.EncodeToString(sig) }
func DecodeSignatureHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(cleanHex(s))
	if err != nil || len(b) != ed25519.SignatureSize {
		return nil, ErrInvalidEncoding
	}
	return b, nil
}
