package registry

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestIsValidDomain(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"my-domain.org",
		"domain123.net",
		"localhost",
		"a.b.c.d.e.f",
		"EXAMPLE.COM",
		"example.com.",
	}
	for _, d := range valid {
		if !IsValidDomain(d) {
			t.Errorf("expected %q to be valid domain", d)
		}
	}

	invalid := []string{
		"",
		"   ",
		"../traversal",
		"domain/slash",
		"domain\\backslash",
		"domain with spaces.com",
		"-startdash.com",
		"enddash-.com",
		string(bytes.Repeat([]byte("a"), 260)),
	}
	for _, d := range invalid {
		if IsValidDomain(d) {
			t.Errorf("expected %q to be invalid domain", d)
		}
	}
}

func TestDomainKeyPair_GenerateAndBasic(t *testing.T) {
	// Invalid domain
	if _, err := GenerateDomainKeyPair("../invalid"); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain, got %v", err)
	}

	dkp, err := GenerateDomainKeyPair("example.com")
	if err != nil {
		t.Fatalf("unexpected error generating keypair: %v", err)
	}
	if dkp.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", dkp.Domain)
	}
	if len(dkp.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("expected public key size 32, got %d", len(dkp.PublicKey))
	}
	if len(dkp.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size 64, got %d", len(dkp.PrivateKey))
	}

	if dkp.PublicKeyHex() != EncodePublicKeyHex(dkp.PublicKey) {
		t.Errorf("PublicKeyHex mismatch")
	}
	if dkp.DNSTXTRecord() != "kademlia-pk="+dkp.PublicKeyHex() {
		t.Errorf("DNSTXTRecord mismatch: got %s", dkp.DNSTXTRecord())
	}
}

func TestNewDomainKeyPair_ValidationAndCopy(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()

	// Invalid domain
	if _, err := NewDomainKeyPair("bad/domain", pub, priv); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain, got %v", err)
	}

	// Invalid pub key
	if _, err := NewDomainKeyPair("example.com", pub[:10], priv); !errors.Is(err, ErrInvalidPublicKeySize) {
		t.Errorf("expected ErrInvalidPublicKeySize, got %v", err)
	}

	// Invalid priv key
	if _, err := NewDomainKeyPair("example.com", pub, priv[:20]); !errors.Is(err, ErrInvalidPrivateKeySize) {
		t.Errorf("expected ErrInvalidPrivateKeySize, got %v", err)
	}

	// Successful creation and defensive copy
	dkp, err := NewDomainKeyPair("Example.com.", pub, priv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dkp.Domain != "example.com" {
		t.Errorf("expected normalized domain example.com, got %s", dkp.Domain)
	}

	// Mutate external buffers
	pub[0] ^= 0xFF
	priv[0] ^= 0xFF
	if bytes.Equal(pub, dkp.PublicKey) {
		t.Error("NewDomainKeyPair did not make defensive copy of public key")
	}
	if bytes.Equal(priv, dkp.PrivateKey) {
		t.Error("NewDomainKeyPair did not make defensive copy of private key")
	}
}

func TestDomainKeyPair_SignAndVerify(t *testing.T) {
	dkp, err := GenerateDomainKeyPair("pkg-registry.org")
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	msg := []byte("v1.0.0 package metadata")
	sig, err := dkp.Sign(msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Valid verify
	if err := dkp.Verify(msg, sig); err != nil {
		t.Errorf("verify failed: %v", err)
	}

	// Tampered data
	if err := dkp.Verify([]byte("v1.0.1 package metadata"), sig); !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Errorf("expected ErrSignatureVerificationFailed for tampered message, got %v", err)
	}

	// Tampered signature
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[10] ^= 0xEE
	if err := dkp.Verify(msg, tamperedSig); !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Errorf("expected ErrSignatureVerificationFailed for tampered signature, got %v", err)
	}
}

func TestDomainKeyPair_JSONMarshaling(t *testing.T) {
	dkp, err := GenerateDomainKeyPair("json-test.net")
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	jsonData, err := dkp.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var loaded DomainKeyPair
	if err := loaded.UnmarshalJSON(jsonData); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if loaded.Domain != dkp.Domain {
		t.Errorf("domain mismatch: %s vs %s", loaded.Domain, dkp.Domain)
	}
	if !bytes.Equal(loaded.PublicKey, dkp.PublicKey) {
		t.Errorf("public key mismatch")
	}
	if !bytes.Equal(loaded.PrivateKey, dkp.PrivateKey) {
		t.Errorf("private key mismatch")
	}

	// Invalid JSON payload
	if err := loaded.UnmarshalJSON([]byte(`{"domain": "bad/domain"}`)); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain for invalid domain in JSON, got %v", err)
	}
	if err := loaded.UnmarshalJSON([]byte(`{"domain": "foo.com", "public_key": "not-valid-pk"}`)); err == nil {
		t.Errorf("expected error for corrupt public key in JSON")
	}
	if err := loaded.UnmarshalJSON([]byte(`{"domain": "foo.com", "public_key": "` + dkp.PublicKeyHex() + `", "private_key": "not-valid-sk"}`)); err == nil {
		t.Errorf("expected error for corrupt private key in JSON")
	}
	if err := loaded.UnmarshalJSON([]byte(`not json`)); err == nil {
		t.Errorf("expected error for garbage JSON")
	}
}

func TestDomainKeyPair_FilePersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keymanager_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dkp, err := GenerateDomainKeyPair("persisted.org")
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	filePath := filepath.Join(tempDir, "keys", "sub", "persisted.org.json")
	if err := dkp.SaveToFile(filePath); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Check file permissions (0600)
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %o", perm)
	}

	// Load file
	loaded, err := LoadDomainKeyPair(filePath)
	if err != nil {
		t.Fatalf("LoadDomainKeyPair failed: %v", err)
	}
	if loaded.Domain != dkp.Domain {
		t.Errorf("loaded domain mismatch: %s", loaded.Domain)
	}
	if !bytes.Equal(loaded.PublicKey, dkp.PublicKey) {
		t.Errorf("loaded public key mismatch")
	}
	if !bytes.Equal(loaded.PrivateKey, dkp.PrivateKey) {
		t.Errorf("loaded private key mismatch")
	}

	// Load non-existent file
	if _, err := LoadDomainKeyPair(filepath.Join(tempDir, "does-not-exist.json")); err == nil {
		t.Errorf("expected error loading non-existent file")
	}

	// Load corrupted file
	corruptPath := filepath.Join(tempDir, "corrupt.json")
	_ = os.WriteFile(corruptPath, []byte("invalid data"), 0600)
	if _, err := LoadDomainKeyPair(corruptPath); err == nil {
		t.Errorf("expected error loading corrupted key file")
	}
}

func TestKeyManager_InMemory(t *testing.T) {
	km, err := NewKeyManager("")
	if err != nil {
		t.Fatalf("failed to create in-memory KeyManager: %v", err)
	}

	dkp, err := km.Generate("memory-domain.com")
	if err != nil {
		t.Fatalf("failed to generate key in manager: %v", err)
	}

	got, exists := km.Get("MEMORY-DOMAIN.COM.")
	if !exists || got != dkp {
		t.Errorf("failed to retrieve cached domain key")
	}

	loaded, err := km.Load("memory-domain.com")
	if err != nil || loaded != dkp {
		t.Errorf("failed to load cached domain key: %v", err)
	}

	// Sign
	msg := []byte("payload to sign")
	sig, err := km.Sign("memory-domain.com", msg)
	if err != nil {
		t.Fatalf("failed to sign message: %v", err)
	}
	if err := dkp.Verify(msg, sig); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}

	// Sign for non-existent domain
	if _, err := km.Sign("unknown.org", msg); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}

	// Add pre-existing key
	otherPair, _ := GenerateDomainKeyPair("added.org")
	if err := km.Add(otherPair); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if _, exists := km.Get("added.org"); !exists {
		t.Errorf("added domain not found in Get")
	}

	domains := km.ListDomains()
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(domains))
	}
}

func TestKeyManager_FilesystemPersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "km_fs_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	km1, err := NewKeyManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create KeyManager: %v", err)
	}

	dkp, err := km1.Generate("persisted-pkg.net")
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	// Initialize fresh KeyManager with same baseDir (empty memory cache)
	km2, err := NewKeyManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create second KeyManager: %v", err)
	}

	// Key is not in memory initially
	if _, exists := km2.Get("persisted-pkg.net"); exists {
		t.Errorf("expected key not in memory yet")
	}

	// Load should read from disk and populate memory cache
	loaded, err := km2.Load("persisted-pkg.net")
	if err != nil {
		t.Fatalf("failed to load from disk in second manager: %v", err)
	}
	if loaded.Domain != dkp.Domain || !bytes.Equal(loaded.PublicKey, dkp.PublicKey) {
		t.Errorf("loaded key does not match generated key")
	}

	// Subsequent Get succeeds
	if _, exists := km2.Get("persisted-pkg.net"); !exists {
		t.Errorf("expected key in memory after Load")
	}

	// Path traversal attempt
	if _, err := km2.Load("../evil"); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain for traversal load, got %v", err)
	}
	if _, err := km2.Generate("bad/name"); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain for invalid generate, got %v", err)
	}
	if err := km2.Save(&DomainKeyPair{Domain: "bad/domain"}); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain for invalid save, got %v", err)
	}
	if err := km2.Add(&DomainKeyPair{Domain: "bad/domain"}); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain for invalid add, got %v", err)
	}
}

func TestKeyManager_Concurrency(t *testing.T) {
	km, _ := NewKeyManager("")

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			domain := fmt.Sprintf("node%d.test", id)
			dkp, err := km.Generate(domain)
			if err != nil {
				t.Errorf("generate error: %v", err)
				return
			}
			msg := []byte("ping payload")
			sig, err := km.Sign(domain, msg)
			if err != nil {
				t.Errorf("sign error: %v", err)
				return
			}
			if err := dkp.Verify(msg, sig); err != nil {
				t.Errorf("verify error: %v", err)
			}
			_ = km.ListDomains()
		}(i)
	}
	wg.Wait()
}

func TestKeyManager_AdditionalEdgeCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "km_edge_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// SaveToFile with no dir path
	localFile := filepath.Join(tempDir, "local.json")
	dkp, err := GenerateDomainKeyPair("local.net")
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if err := dkp.SaveToFile(localFile); err != nil {
		t.Fatalf("SaveToFile without nested directory failed: %v", err)
	}

	// NewKeyManager error when baseDir conflicts with a file
	filePath := filepath.Join(tempDir, "some-file")
	if err := os.WriteFile(filePath, []byte("data"), 0600); err != nil {
		t.Fatalf("failed to create dummy file: %v", err)
	}
	if _, err := NewKeyManager(filePath); err == nil {
		t.Errorf("expected error from NewKeyManager when path is a file")
	}

	// KeyManager Load when not found on disk wraps ErrKeyNotFound
	km, err := NewKeyManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create KeyManager: %v", err)
	}
	if _, err := km.Load("nonexistent.com"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound from Load on nonexistent key, got %v", err)
	}
}

func TestDomainKeyPair_MismatchedKeys(t *testing.T) {
	pub1, _, _ := GenerateKeyPair()
	_, priv2, _ := GenerateKeyPair()

	// NewDomainKeyPair with Alice's pub and Bob's priv
	_, err := NewDomainKeyPair("mismatch.org", pub1, priv2)
	if !errors.Is(err, ErrMismatchedKeyPair) {
		t.Errorf("expected ErrMismatchedKeyPair on NewDomainKeyPair with mismatched keys, got %v", err)
	}
}

func TestDomainKeyPair_MismatchedKeysJSON(t *testing.T) {
	pub1, _, _ := GenerateKeyPair()
	_, priv2, _ := GenerateKeyPair()

	badJSON := fmt.Sprintf(`{
		"domain": "mismatch.org",
		"public_key": "%s",
		"private_key": "%s"
	}`, EncodePublicKeyHex(pub1), EncodePrivateKeyHex(priv2))

	var dkp DomainKeyPair
	err := dkp.UnmarshalJSON([]byte(badJSON))
	if !errors.Is(err, ErrMismatchedKeyPair) {
		t.Errorf("expected ErrMismatchedKeyPair on UnmarshalJSON with mismatched keys, got %v", err)
	}
}

func TestDomainKeyPair_PublicKeyBase64(t *testing.T) {
	dkp, err := GenerateDomainKeyPair("b64test.org")
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if dkp.PublicKeyBase64() != EncodePublicKeyBase64(dkp.PublicKey) {
		t.Errorf("PublicKeyBase64 mismatch")
	}

	var nilDkp *DomainKeyPair
	if nilDkp.PublicKeyBase64() != "" || nilDkp.PublicKeyHex() != "" || nilDkp.DNSTXTRecord() != "" {
		t.Errorf("expected empty strings on nil DomainKeyPair helper methods")
	}
	if _, err := nilDkp.Sign([]byte("msg")); err == nil {
		t.Errorf("expected error signing on nil DomainKeyPair")
	}
	if err := nilDkp.Verify([]byte("msg"), []byte("sig")); err == nil {
		t.Errorf("expected error verifying on nil DomainKeyPair")
	}
}

func TestDomainKeyPair_FilePermissionsPreExisting(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "km_perm_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "existing-file.json")
	// Pre-create file with permissive mode 0666
	if err := os.WriteFile(filePath, []byte("{}"), 0666); err != nil {
		t.Fatalf("failed to pre-create file: %v", err)
	}

	dkp, _ := GenerateDomainKeyPair("secure.org")
	if err := dkp.SaveToFile(filePath); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected permissions 0600 on pre-existing file after SaveToFile, got %o", perm)
	}
}

func TestKeyManager_NilGuardsAndSaveRollback(t *testing.T) {
	km, _ := NewKeyManager("")

	// Nil guards
	if err := km.Save(nil); err == nil {
		t.Error("expected error saving nil DomainKeyPair")
	}
	if err := km.Add(nil); err == nil {
		t.Error("expected error adding nil DomainKeyPair")
	}

	// Save failure on unwriteable directory does not pollute memory
	tempDir, _ := os.MkdirTemp("", "km_ro_*")
	defer os.RemoveAll(tempDir)

	kmDisk, _ := NewKeyManager(tempDir)
	// Create read-only directory
	roDir := filepath.Join(tempDir, "ro_sub")
	_ = os.MkdirAll(roDir, 0500)
	kmReadOnly, _ := NewKeyManager(roDir)

	dkp, _ := GenerateDomainKeyPair("fail-save.org")
	err := kmReadOnly.Save(dkp)
	if err == nil {
		t.Log("Note: running as root might bypass 0500 permission, test skipped")
	} else {
		// Verify memory was not updated
		if _, exists := kmReadOnly.Get("fail-save.org"); exists {
			t.Error("kmReadOnly memory cache was updated despite disk write failure")
		}
	}

	_ = kmDisk
}

func TestKeyManager_DeleteAndPersistedDiscovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "km_del_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	km, _ := NewKeyManager(tempDir)
	_, _ = km.Generate("delta.com")
	_, _ = km.Generate("alpha.com")
	_, _ = km.Generate("charlie.com")

	// Fresh KeyManager on same dir has empty in-memory cache
	freshKM, _ := NewKeyManager(tempDir)
	domains := freshKM.ListDomains()
	if len(domains) != 3 {
		t.Fatalf("expected 3 domains discovered from disk, got %d", len(domains))
	}
	// Sorted order check
	if domains[0] != "alpha.com" || domains[1] != "charlie.com" || domains[2] != "delta.com" {
		t.Errorf("expected sorted domains [alpha.com charlie.com delta.com], got %v", domains)
	}

	// Delete delta.com
	if err := km.Delete("delta.com"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, exists := km.Get("delta.com"); exists {
		t.Error("delta.com still exists in memory after Delete")
	}
	if _, err := km.Load("delta.com"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound after Delete, got %v", err)
	}

	// Delete invalid domain
	if err := km.Delete("bad/domain"); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain on Delete, got %v", err)
	}
}
