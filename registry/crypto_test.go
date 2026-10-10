package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("expected pub key length %d, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("expected priv key length %d, got %d", ed25519.PrivateKeySize, len(priv))
	}
}

func TestGenerateDomainKeyPair(t *testing.T) {
	dkp, err := GenerateDomainKeyPair("example.com")
	if err != nil {
		t.Fatalf("GenerateDomainKeyPair failed: %v", err)
	}
	if dkp.Domain != "example.com" {
		t.Fatalf("expected domain example.com, got %s", dkp.Domain)
	}
	if len(dkp.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("invalid public key size: %d", len(dkp.PublicKey))
	}

	// Invalid domain
	if _, err := GenerateDomainKeyPair("../bad"); err == nil {
		t.Fatal("expected error for invalid domain")
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello kademlia package registry")

	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("expected sig len %d, got %d", ed25519.SignatureSize, len(sig))
	}

	if err := Verify(pub, msg, sig); err != nil {
		t.Fatalf("Verify failed on valid signature: %v", err)
	}

	// Tampered message
	tampered := []byte("hello kademlia package registry tampered")
	if err := Verify(pub, tampered, sig); !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Fatalf("expected ErrSignatureVerificationFailed on tampered msg, got %v", err)
	}

	// Different public key
	otherPub, _, _ := GenerateKeyPair()
	if err := Verify(otherPub, msg, sig); !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Fatalf("expected ErrSignatureVerificationFailed on different pub key, got %v", err)
	}

	// Invalid pub key or signature lengths
	if err := Verify([]byte("short"), msg, sig); !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Fatalf("expected failure on short pub key, got %v", err)
	}
	if err := Verify(pub, msg, []byte("short")); !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Fatalf("expected failure on short sig, got %v", err)
	}
}

func TestDomainKeyPair_Methods(t *testing.T) {
	dkp, err := GenerateDomainKeyPair("registry.org")
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("package data")
	sig, err := dkp.Sign(msg)
	if err != nil {
		t.Fatalf("dkp.Sign failed: %v", err)
	}
	if err := dkp.Verify(msg, sig); err != nil {
		t.Fatalf("dkp.Verify failed: %v", err)
	}

	hexKey := dkp.PublicKeyHex()
	if len(hexKey) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(hexKey))
	}
	txtRec := dkp.DNSTXTRecord()
	if txtRec != DefaultDNSTXTPrefix+hexKey {
		t.Fatalf("unexpected TXT record: %s", txtRec)
	}

	// Nil receiver checks
	var nilDKP *DomainKeyPair
	if _, err := nilDKP.Sign(msg); err == nil {
		t.Fatal("expected error on nilDKP.Sign")
	}
	if err := nilDKP.Verify(msg, sig); err == nil {
		t.Fatal("expected error on nilDKP.Verify")
	}
	if nilDKP.PublicKeyHex() != "" {
		t.Fatal("expected empty PublicKeyHex on nil")
	}
	if nilDKP.DNSTXTRecord() != "" {
		t.Fatal("expected empty DNSTXTRecord on nil")
	}
}

func TestHexEncoding(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	msg := []byte("data")
	sig, _ := Sign(priv, msg)

	// Public Key Hex
	pubHex := EncodePublicKeyHex(pub)
	decPub, err := DecodePublicKeyHex(pubHex)
	if err != nil || !bytes.Equal(pub, decPub) {
		t.Fatalf("DecodePublicKeyHex mismatch: %v", err)
	}
	// With 0x prefix and spaces
	decPub2, err := DecodePublicKeyHex("  0x" + pubHex + "  ")
	if err != nil || !bytes.Equal(pub, decPub2) {
		t.Fatalf("DecodePublicKeyHex with 0x failed: %v", err)
	}
	// Invalid
	if _, err := DecodePublicKeyHex("not-hex"); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatal("expected ErrInvalidEncoding on invalid hex")
	}
	if _, err := DecodePublicKeyHex("abcd"); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatal("expected ErrInvalidEncoding on short hex")
	}

	// Private Key Hex
	privHex := EncodePrivateKeyHex(priv)
	decPriv, err := DecodePrivateKeyHex(privHex)
	if err != nil || !bytes.Equal(priv, decPriv) {
		t.Fatalf("DecodePrivateKeyHex mismatch: %v", err)
	}
	// Seed (32 bytes = 64 hex chars)
	seedHex := hex.EncodeToString(priv[:32])
	decSeedPriv, err := DecodePrivateKeyHex(seedHex)
	if err != nil || !bytes.Equal(priv, decSeedPriv) {
		t.Fatalf("DecodePrivateKeyHex from seed failed: %v", err)
	}
	// Invalid
	if _, err := DecodePrivateKeyHex("xyz"); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatal("expected ErrInvalidEncoding on invalid private key hex")
	}

	// Signature Hex
	sigHex := EncodeSignatureHex(sig)
	decSig, err := DecodeSignatureHex(sigHex)
	if err != nil || !bytes.Equal(sig, decSig) {
		t.Fatalf("DecodeSignatureHex mismatch: %v", err)
	}
	// Invalid
	if _, err := DecodeSignatureHex("xyz"); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatal("expected ErrInvalidEncoding on invalid signature hex")
	}
	if _, err := DecodeSignatureHex(hex.EncodeToString([]byte("short"))); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatal("expected ErrInvalidEncoding on short signature hex")
	}
}
