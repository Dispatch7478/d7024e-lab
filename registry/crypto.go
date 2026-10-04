package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidPublicKeySize indicates an Ed25519 public key is not 32 bytes.
	ErrInvalidPublicKeySize = errors.New("invalid public key size: must be 32 bytes")
	// ErrInvalidPrivateKeySize indicates an Ed25519 private key is not 64 bytes.
	ErrInvalidPrivateKeySize = errors.New("invalid private key size: must be 64 bytes")
	// ErrInvalidSignatureSize indicates an Ed25519 signature is not 64 bytes.
	ErrInvalidSignatureSize = errors.New("invalid signature size: must be 64 bytes")
	// ErrInvalidSeedSize indicates an Ed25519 seed is not 32 bytes.
	ErrInvalidSeedSize = errors.New("invalid seed size: must be 32 bytes")
	// ErrSignatureVerificationFailed indicates that verification of a digital signature failed.
	ErrSignatureVerificationFailed = errors.New("signature verification failed")
	// ErrInvalidEncoding indicates an input string could not be parsed as valid hex or base64.
	ErrInvalidEncoding = errors.New("invalid key or signature encoding")
	// ErrMismatchedKeyPair indicates that the public key does not correspond to the private key.
	ErrMismatchedKeyPair = errors.New("public key does not match private key")
)

// GenerateKeyPair generates a cryptographically secure random Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// GenerateKeyPairFromSeed deterministically generates an Ed25519 key pair from a 32-byte seed.
func GenerateKeyPairFromSeed(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("%w: got %d bytes", ErrInvalidSeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

// Sign signs a message using the provided Ed25519 private key.
func Sign(priv ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPrivateKeySize, len(priv))
	}
	sig := ed25519.Sign(priv, message)
	return sig, nil
}

// Verify verifies whether a signature is valid for the given public key and message.
// Returns nil if valid, or an error detailing why verification failed.
func Verify(pub ed25519.PublicKey, message []byte, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidPublicKeySize, len(pub))
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidSignatureSize, len(sig))
	}
	if !ed25519.Verify(pub, message, sig) {
		return ErrSignatureVerificationFailed
	}
	return nil
}

// IsValidSignature returns true if the signature is valid for the given message and public key.
func IsValidSignature(pub ed25519.PublicKey, message []byte, sig []byte) bool {
	return Verify(pub, message, sig) == nil
}

// EncodePublicKeyHex returns the hexadecimal string representation of an Ed25519 public key.
func EncodePublicKeyHex(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}

func cleanHex(s string) string {
	c := strings.Trim(strings.TrimSpace(s), "\"'")
	c = strings.TrimPrefix(c, "0x")
	c = strings.TrimPrefix(c, "0X")
	return c
}

// DecodePublicKeyHex decodes a hexadecimal string into an Ed25519 public key (32 bytes).
// It accepts optional "0x" prefix and surrounding quotes.
func DecodePublicKeyHex(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(cleanHex(s))
	if err != nil {
		return nil, fmt.Errorf("%w: hex decode error: %v", ErrInvalidEncoding, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// EncodePrivateKeyHex returns the hexadecimal string representation of an Ed25519 private key.
func EncodePrivateKeyHex(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv)
}

// DecodePrivateKeyHex decodes a hexadecimal string into an Ed25519 private key.
// If the decoded data is 32 bytes (seed), it derives the full 64-byte private key.
// If 64 bytes, it validates internal consistency between the seed and public key halves.
func DecodePrivateKeyHex(s string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(cleanHex(s))
	if err != nil {
		return nil, fmt.Errorf("%w: hex decode error: %v", ErrInvalidEncoding, err)
	}
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), nil
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPrivateKeySize, len(b))
	}
	derived := ed25519.NewKeyFromSeed(b[:32])
	if !bytes.Equal(b[32:], derived[32:]) {
		return nil, fmt.Errorf("%w: inconsistent private key public suffix", ErrMismatchedKeyPair)
	}
	return ed25519.PrivateKey(b), nil
}

// EncodeSignatureHex returns the hexadecimal string representation of an Ed25519 signature.
func EncodeSignatureHex(sig []byte) string {
	return hex.EncodeToString(sig)
}

// DecodeSignatureHex decodes a hexadecimal string into an Ed25519 signature (64 bytes).
// It accepts optional "0x" prefix and surrounding quotes.
func DecodeSignatureHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(cleanHex(s))
	if err != nil {
		return nil, fmt.Errorf("%w: hex decode error: %v", ErrInvalidEncoding, err)
	}
	if len(b) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidSignatureSize, len(b))
	}
	return b, nil
}

// EncodePublicKeyBase64 returns the standard base64 encoding of an Ed25519 public key.
func EncodePublicKeyBase64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodePublicKeyBase64 decodes a base64 string (standard or URL-safe) into an Ed25519 public key.
func DecodePublicKeyBase64(s string) (ed25519.PublicKey, error) {
	clean := strings.Trim(strings.TrimSpace(s), "\"'")
	b, err := decodeBase64Flexible(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode error: %v", ErrInvalidEncoding, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// EncodePrivateKeyBase64 returns the standard base64 encoding of an Ed25519 private key.
func EncodePrivateKeyBase64(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv)
}

// DecodePrivateKeyBase64 decodes a base64 string into an Ed25519 private key.
// If the decoded data is 32 bytes (seed), it derives the full 64-byte private key.
// If 64 bytes, it validates internal consistency between the seed and public key halves.
func DecodePrivateKeyBase64(s string) (ed25519.PrivateKey, error) {
	clean := strings.Trim(strings.TrimSpace(s), "\"'")
	b, err := decodeBase64Flexible(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode error: %v", ErrInvalidEncoding, err)
	}
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), nil
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPrivateKeySize, len(b))
	}
	derived := ed25519.NewKeyFromSeed(b[:32])
	if !bytes.Equal(b[32:], derived[32:]) {
		return nil, fmt.Errorf("%w: inconsistent private key public suffix", ErrMismatchedKeyPair)
	}
	return ed25519.PrivateKey(b), nil
}

// EncodeSignatureBase64 returns the standard base64 encoding of an Ed25519 signature.
func EncodeSignatureBase64(sig []byte) string {
	return base64.StdEncoding.EncodeToString(sig)
}

// DecodeSignatureBase64 decodes a base64 string into an Ed25519 signature (64 bytes).
func DecodeSignatureBase64(s string) ([]byte, error) {
	clean := strings.Trim(strings.TrimSpace(s), "\"'")
	b, err := decodeBase64Flexible(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode error: %v", ErrInvalidEncoding, err)
	}
	if len(b) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidSignatureSize, len(b))
	}
	return b, nil
}

// decodeBase64Flexible attempts decoding standard, URL-safe, and unpadded variants.
func decodeBase64Flexible(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("failed to decode base64")
}

// ParsePublicKey auto-detects hex or base64 format to decode an Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	clean := strings.Trim(strings.TrimSpace(s), "\"'")
	if clean == "" {
		return nil, ErrInvalidEncoding
	}
	unhexed := cleanHex(clean)
	// 32 bytes in hex = 64 characters
	if len(unhexed) == 64 {
		if pub, err := DecodePublicKeyHex(unhexed); err == nil {
			return pub, nil
		}
	}
	// Base64 public key is typically 43 or 44 characters
	if pub, err := DecodePublicKeyBase64(clean); err == nil {
		return pub, nil
	}
	// Fallback attempt hex if length was different but might parse
	if pub, err := DecodePublicKeyHex(unhexed); err == nil {
		return pub, nil
	}
	return nil, fmt.Errorf("%w: cannot parse public key from %q", ErrInvalidEncoding, s)
}

// ParsePrivateKey auto-detects hex or base64 format to decode an Ed25519 private key.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	clean := strings.Trim(strings.TrimSpace(s), "\"'")
	if clean == "" {
		return nil, ErrInvalidEncoding
	}
	unhexed := cleanHex(clean)
	// 64 bytes in hex = 128 chars, 32 bytes seed in hex = 64 chars
	if len(unhexed) == 128 || len(unhexed) == 64 {
		if priv, err := DecodePrivateKeyHex(unhexed); err == nil {
			return priv, nil
		}
	}
	if priv, err := DecodePrivateKeyBase64(clean); err == nil {
		return priv, nil
	}
	if priv, err := DecodePrivateKeyHex(unhexed); err == nil {
		return priv, nil
	}
	return nil, fmt.Errorf("%w: cannot parse private key from input", ErrInvalidEncoding)
}

// ParseSignature auto-detects hex or base64 format to decode an Ed25519 signature.
func ParseSignature(s string) ([]byte, error) {
	clean := strings.Trim(strings.TrimSpace(s), "\"'")
	if clean == "" {
		return nil, ErrInvalidEncoding
	}
	unhexed := cleanHex(clean)
	// 64 bytes in hex = 128 characters
	if len(unhexed) == 128 {
		if sig, err := DecodeSignatureHex(unhexed); err == nil {
			return sig, nil
		}
	}
	if sig, err := DecodeSignatureBase64(clean); err == nil {
		return sig, nil
	}
	if sig, err := DecodeSignatureHex(unhexed); err == nil {
		return sig, nil
	}
	return nil, fmt.Errorf("%w: cannot parse signature from input", ErrInvalidEncoding)
}
