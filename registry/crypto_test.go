package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pub1, priv1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("unexpected error generating key pair: %v", err)
	}
	if len(pub1) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pub1))
	}
	if len(priv1) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(priv1))
	}

	pub2, priv2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("unexpected error generating second key pair: %v", err)
	}
	if bytes.Equal(pub1, pub2) {
		t.Error("two independently generated public keys should not be identical")
	}
	if bytes.Equal(priv1, priv2) {
		t.Error("two independently generated private keys should not be identical")
	}
}

func TestGenerateKeyPairFromSeed(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	pub1, priv1, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("failed to generate key pair from valid seed: %v", err)
	}
	if len(pub1) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pub1))
	}
	if len(priv1) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(priv1))
	}

	// Deterministic reproduction
	pub2, priv2, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("failed to regenerate key pair from seed: %v", err)
	}
	if !bytes.Equal(pub1, pub2) || !bytes.Equal(priv1, priv2) {
		t.Error("deterministic key generation produced different keys for same seed")
	}

	// Invalid seed sizes
	if _, _, err := GenerateKeyPairFromSeed([]byte("too-short")); !errors.Is(err, ErrInvalidSeedSize) {
		t.Errorf("expected ErrInvalidSeedSize for short seed, got %v", err)
	}
	longSeed := make([]byte, 64)
	if _, _, err := GenerateKeyPairFromSeed(longSeed); !errors.Is(err, ErrInvalidSeedSize) {
		t.Errorf("expected ErrInvalidSeedSize for long seed, got %v", err)
	}
}

func TestSignAndVerify_Valid(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	messages := [][]byte{
		[]byte("hello decentralized registry"),
		[]byte(""),
		bytes.Repeat([]byte("large-blob-data"), 1000),
	}

	for _, msg := range messages {
		sig, err := Sign(priv, msg)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}
		if len(sig) != ed25519.SignatureSize {
			t.Fatalf("expected signature size %d, got %d", ed25519.SignatureSize, len(sig))
		}

		if err := Verify(pub, msg, sig); err != nil {
			t.Errorf("verify failed for valid message: %v", err)
		}
		if !IsValidSignature(pub, msg, sig) {
			t.Errorf("IsValidSignature returned false for valid message")
		}
	}
}

func TestSign_InvalidKey(t *testing.T) {
	invalidPriv := make([]byte, 32) // should be 64
	_, err := Sign(invalidPriv, []byte("msg"))
	if !errors.Is(err, ErrInvalidPrivateKeySize) {
		t.Errorf("expected ErrInvalidPrivateKeySize, got %v", err)
	}
}

func TestVerify_TamperedData(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	msg := []byte("original package payload v1.0.0")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tampered message
	tamperedMsg := []byte("original package payload v1.0.1")
	if err := Verify(pub, tamperedMsg, sig); !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Errorf("expected ErrSignatureVerificationFailed for tampered message, got %v", err)
	}
	if IsValidSignature(pub, tamperedMsg, sig) {
		t.Errorf("expected IsValidSignature false for tampered message")
	}

	// Tampered signature
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0xFF
	if err := Verify(pub, msg, tamperedSig); !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Errorf("expected ErrSignatureVerificationFailed for tampered signature, got %v", err)
	}
	if IsValidSignature(pub, msg, tamperedSig) {
		t.Errorf("expected IsValidSignature false for tampered signature")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv1, _ := GenerateKeyPair()
	pub2, _, _ := GenerateKeyPair()

	msg := []byte("package data signed by key 1")
	sig, err := Sign(priv1, msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Verify using key 2
	if err := Verify(pub2, msg, sig); !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Errorf("expected ErrSignatureVerificationFailed when verifying with wrong key, got %v", err)
	}
	if IsValidSignature(pub2, msg, sig) {
		t.Errorf("expected IsValidSignature false for wrong key")
	}
}

func TestVerify_InvalidSizes(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	sig, _ := Sign(priv, []byte("test"))

	// Invalid pub key size
	if err := Verify(pub[:10], []byte("test"), sig); !errors.Is(err, ErrInvalidPublicKeySize) {
		t.Errorf("expected ErrInvalidPublicKeySize, got %v", err)
	}

	// Invalid signature size
	if err := Verify(pub, []byte("test"), sig[:20]); !errors.Is(err, ErrInvalidSignatureSize) {
		t.Errorf("expected ErrInvalidSignatureSize, got %v", err)
	}
}

func TestHexEncoding_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	sig, _ := Sign(priv, []byte("test hex encoding"))

	// Public Key
	pubHex := EncodePublicKeyHex(pub)
	pubDec, err := DecodePublicKeyHex(pubHex)
	if err != nil {
		t.Fatalf("decode pub key hex failed: %v", err)
	}
	if !bytes.Equal(pub, pubDec) {
		t.Errorf("pub key hex round trip mismatch")
	}

	// Private Key
	privHex := EncodePrivateKeyHex(priv)
	privDec, err := DecodePrivateKeyHex(privHex)
	if err != nil {
		t.Fatalf("decode priv key hex failed: %v", err)
	}
	if !bytes.Equal(priv, privDec) {
		t.Errorf("priv key hex round trip mismatch")
	}

	// 32-byte seed in DecodePrivateKeyHex
	seedHex := privHex[:64] // first 32 bytes are seed
	privFromSeed, err := DecodePrivateKeyHex(seedHex)
	if err != nil {
		t.Fatalf("decode priv key hex from seed failed: %v", err)
	}
	if !bytes.Equal(priv, privFromSeed) {
		t.Errorf("priv key from seed did not match original private key")
	}

	// Signature
	sigHex := EncodeSignatureHex(sig)
	sigDec, err := DecodeSignatureHex(sigHex)
	if err != nil {
		t.Fatalf("decode signature hex failed: %v", err)
	}
	if !bytes.Equal(sig, sigDec) {
		t.Errorf("signature hex round trip mismatch")
	}
}

func TestHexEncoding_Invalid(t *testing.T) {
	// Not hex
	if _, err := DecodePublicKeyHex("not-hex-chars!"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding, got %v", err)
	}
	if _, err := DecodePrivateKeyHex("not-hex-chars!"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding, got %v", err)
	}
	if _, err := DecodeSignatureHex("not-hex-chars!"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding, got %v", err)
	}

	// Wrong length hex
	if _, err := DecodePublicKeyHex("abcd"); !errors.Is(err, ErrInvalidPublicKeySize) {
		t.Errorf("expected ErrInvalidPublicKeySize, got %v", err)
	}
	if _, err := DecodePrivateKeyHex("abcd"); !errors.Is(err, ErrInvalidPrivateKeySize) {
		t.Errorf("expected ErrInvalidPrivateKeySize, got %v", err)
	}
	if _, err := DecodeSignatureHex("abcd"); !errors.Is(err, ErrInvalidSignatureSize) {
		t.Errorf("expected ErrInvalidSignatureSize, got %v", err)
	}
}

func TestBase64Encoding_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	sig, _ := Sign(priv, []byte("test base64 encoding"))

	// Public Key
	pubB64 := EncodePublicKeyBase64(pub)
	pubDec, err := DecodePublicKeyBase64(pubB64)
	if err != nil {
		t.Fatalf("decode pub key base64 failed: %v", err)
	}
	if !bytes.Equal(pub, pubDec) {
		t.Errorf("pub key base64 round trip mismatch")
	}

	// Private Key
	privB64 := EncodePrivateKeyBase64(priv)
	privDec, err := DecodePrivateKeyBase64(privB64)
	if err != nil {
		t.Fatalf("decode priv key base64 failed: %v", err)
	}
	if !bytes.Equal(priv, privDec) {
		t.Errorf("priv key base64 round trip mismatch")
	}

	// 32-byte seed in DecodePrivateKeyBase64
	seedB64 := EncodePublicKeyBase64(ed25519.PublicKey(priv[:32]))
	privFromSeed, err := DecodePrivateKeyBase64(seedB64)
	if err != nil {
		t.Fatalf("decode priv key base64 from seed failed: %v", err)
	}
	if !bytes.Equal(priv, privFromSeed) {
		t.Errorf("priv key from base64 seed did not match original")
	}

	// Signature
	sigB64 := EncodeSignatureBase64(sig)
	sigDec, err := DecodeSignatureBase64(sigB64)
	if err != nil {
		t.Fatalf("decode signature base64 failed: %v", err)
	}
	if !bytes.Equal(sig, sigDec) {
		t.Errorf("signature base64 round trip mismatch")
	}
}

func TestBase64Encoding_Invalid(t *testing.T) {
	if _, err := DecodePublicKeyBase64("!!!"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding, got %v", err)
	}
	if _, err := DecodePrivateKeyBase64("!!!"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding, got %v", err)
	}
	if _, err := DecodeSignatureBase64("!!!"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding, got %v", err)
	}

	// Wrong length decoded base64 (e.g. 4 bytes base64 "AAAA")
	if _, err := DecodePublicKeyBase64("AAAA"); !errors.Is(err, ErrInvalidPublicKeySize) {
		t.Errorf("expected ErrInvalidPublicKeySize, got %v", err)
	}
	if _, err := DecodePrivateKeyBase64("AAAA"); !errors.Is(err, ErrInvalidPrivateKeySize) {
		t.Errorf("expected ErrInvalidPrivateKeySize, got %v", err)
	}
	if _, err := DecodeSignatureBase64("AAAA"); !errors.Is(err, ErrInvalidSignatureSize) {
		t.Errorf("expected ErrInvalidSignatureSize, got %v", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}

	// Parse from hex
	parsedHex, err := ParsePublicKey(EncodePublicKeyHex(pub))
	if err != nil || !bytes.Equal(pub, parsedHex) {
		t.Errorf("ParsePublicKey(hex) failed: %v", err)
	}

	// Parse from base64
	parsedB64, err := ParsePublicKey(EncodePublicKeyBase64(pub))
	if err != nil || !bytes.Equal(pub, parsedB64) {
		t.Errorf("ParsePublicKey(base64) failed: %v", err)
	}

	// Parse with spaces
	parsedSpaced, err := ParsePublicKey("  " + EncodePublicKeyHex(pub) + " \n")
	if err != nil || !bytes.Equal(pub, parsedSpaced) {
		t.Errorf("ParsePublicKey with whitespace failed: %v", err)
	}

	// Empty and invalid
	if _, err := ParsePublicKey(""); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding for empty, got %v", err)
	}
	if _, err := ParsePublicKey("invalid-key-data"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding for garbage, got %v", err)
	}
}

func TestParsePrivateKey(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}

	// Parse 64-byte private key from hex
	p1, err := ParsePrivateKey(EncodePrivateKeyHex(priv))
	if err != nil || !bytes.Equal(priv, p1) {
		t.Errorf("ParsePrivateKey(hex) failed: %v", err)
	}

	// Parse 32-byte seed from hex
	p2, err := ParsePrivateKey(EncodePublicKeyHex(ed25519.PublicKey(priv[:32])))
	if err != nil || !bytes.Equal(priv, p2) {
		t.Errorf("ParsePrivateKey(seed hex) failed: %v", err)
	}

	// Parse 64-byte private key from base64
	p3, err := ParsePrivateKey(EncodePrivateKeyBase64(priv))
	if err != nil || !bytes.Equal(priv, p3) {
		t.Errorf("ParsePrivateKey(base64) failed: %v", err)
	}

	// Parse 32-byte seed from base64
	p4, err := ParsePrivateKey(EncodePublicKeyBase64(ed25519.PublicKey(priv[:32])))
	if err != nil || !bytes.Equal(priv, p4) {
		t.Errorf("ParsePrivateKey(seed base64) failed: %v", err)
	}

	// Empty and invalid
	if _, err := ParsePrivateKey(""); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding for empty, got %v", err)
	}
	if _, err := ParsePrivateKey("invalid-key"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding for invalid, got %v", err)
	}
}

func TestParseSignature(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	sig, _ := Sign(priv, []byte("payload"))

	// Parse from hex
	s1, err := ParseSignature(EncodeSignatureHex(sig))
	if err != nil || !bytes.Equal(sig, s1) {
		t.Errorf("ParseSignature(hex) failed: %v", err)
	}

	// Parse from base64
	s2, err := ParseSignature(EncodeSignatureBase64(sig))
	if err != nil || !bytes.Equal(sig, s2) {
		t.Errorf("ParseSignature(base64) failed: %v", err)
	}

	// Empty and invalid
	if _, err := ParseSignature(""); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding for empty, got %v", err)
	}
	if _, err := ParseSignature("invalid-sig"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding for invalid, got %v", err)
	}
}

func TestBase64_UnpaddedAndURLVariants(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	sig, _ := Sign(priv, []byte("variant test"))

	// RawURLEncoding (unpadded URL-safe)
	rawURLPub := base64.RawURLEncoding.EncodeToString(pub)
	parsedPub, err := ParsePublicKey(rawURLPub)
	if err != nil || !bytes.Equal(pub, parsedPub) {
		t.Errorf("ParsePublicKey with RawURLEncoding failed: %v", err)
	}

	rawURLSig := base64.RawURLEncoding.EncodeToString(sig)
	parsedSig, err := ParseSignature(rawURLSig)
	if err != nil || !bytes.Equal(sig, parsedSig) {
		t.Errorf("ParseSignature with RawURLEncoding failed: %v", err)
	}

	// RawStdEncoding
	rawStdPub := base64.RawStdEncoding.EncodeToString(pub)
	parsedPub2, err := ParsePublicKey(rawStdPub)
	if err != nil || !bytes.Equal(pub, parsedPub2) {
		t.Errorf("ParsePublicKey with RawStdEncoding failed: %v", err)
	}

	// decodeBase64Flexible error
	if _, err := decodeBase64Flexible("invalid!base64!"); err == nil {
		t.Errorf("expected error from decodeBase64Flexible on invalid input")
	}
}

func TestHexEncoding_0xPrefix(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	sig, _ := Sign(priv, []byte("test"))

	// 0x and 0X public key hex
	pubHex := "0x" + EncodePublicKeyHex(pub)
	decPub, err := DecodePublicKeyHex(pubHex)
	if err != nil || !bytes.Equal(pub, decPub) {
		t.Fatalf("DecodePublicKeyHex with 0x failed: %v", err)
	}

	pubHexUpper := "0X" + EncodePublicKeyHex(pub)
	decPubUpper, err := DecodePublicKeyHex(pubHexUpper)
	if err != nil || !bytes.Equal(pub, decPubUpper) {
		t.Fatalf("DecodePublicKeyHex with 0X failed: %v", err)
	}

	// 0x and 0X private key hex
	privHex := "0x" + EncodePrivateKeyHex(priv)
	decPriv, err := DecodePrivateKeyHex(privHex)
	if err != nil || !bytes.Equal(priv, decPriv) {
		t.Fatalf("DecodePrivateKeyHex with 0x failed: %v", err)
	}

	// 0x signature hex
	sigHex := "0x" + EncodeSignatureHex(sig)
	decSig, err := DecodeSignatureHex(sigHex)
	if err != nil || !bytes.Equal(sig, decSig) {
		t.Fatalf("DecodeSignatureHex with 0x failed: %v", err)
	}

	// Parse with 0x prefix
	parsedPub, err := ParsePublicKey(pubHex)
	if err != nil || !bytes.Equal(pub, parsedPub) {
		t.Fatalf("ParsePublicKey with 0x failed: %v", err)
	}

	parsedPriv, err := ParsePrivateKey(privHex)
	if err != nil || !bytes.Equal(priv, parsedPriv) {
		t.Fatalf("ParsePrivateKey with 0x failed: %v", err)
	}

	parsedSig, err := ParseSignature(sigHex)
	if err != nil || !bytes.Equal(sig, parsedSig) {
		t.Fatalf("ParseSignature with 0x failed: %v", err)
	}
}

func TestPrivateKey_InconsistentPublicSuffix(t *testing.T) {
	_, priv, _ := GenerateKeyPair()

	// Corrupt the public key half (priv[32:]) of the 64-byte private key
	corrupted := make([]byte, len(priv))
	copy(corrupted, priv)
	corrupted[32] ^= 0xFF

	corruptHex := EncodePrivateKeyHex(corrupted)
	if _, err := DecodePrivateKeyHex(corruptHex); !errors.Is(err, ErrMismatchedKeyPair) {
		t.Errorf("expected ErrMismatchedKeyPair for corrupted public suffix in hex, got %v", err)
	}

	corruptB64 := EncodePrivateKeyBase64(corrupted)
	if _, err := DecodePrivateKeyBase64(corruptB64); !errors.Is(err, ErrMismatchedKeyPair) {
		t.Errorf("expected ErrMismatchedKeyPair for corrupted public suffix in b64, got %v", err)
	}
}

func TestParse_WithQuotes(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	sig, _ := Sign(priv, []byte("data"))

	quotedPubHex := "\"" + EncodePublicKeyHex(pub) + "\""
	if p, err := ParsePublicKey(quotedPubHex); err != nil || !bytes.Equal(pub, p) {
		t.Errorf("ParsePublicKey with double quotes failed: %v", err)
	}

	singleQuotedPubHex := "'" + EncodePublicKeyHex(pub) + "'"
	if p, err := ParsePublicKey(singleQuotedPubHex); err != nil || !bytes.Equal(pub, p) {
		t.Errorf("ParsePublicKey with single quotes failed: %v", err)
	}

	quotedSig := "\"" + EncodeSignatureHex(sig) + "\""
	if s, err := ParseSignature(quotedSig); err != nil || !bytes.Equal(sig, s) {
		t.Errorf("ParseSignature with quotes failed: %v", err)
	}
}
