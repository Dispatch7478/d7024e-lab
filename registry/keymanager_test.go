package registry

import (
	"bytes"
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
	}
	for _, d := range invalid {
		if IsValidDomain(d) {
			t.Errorf("expected %q to be invalid domain", d)
		}
	}
}

func TestDomainKeyPair_FilePersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keymanager_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	dkp, err := GenerateDomainKeyPair("persisted.org")
	if err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(tempDir, "sub", "persisted.org.json")
	if err := dkp.SaveToFile(filePath); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	loaded, err := LoadDomainKeyPair(filePath)
	if err != nil {
		t.Fatalf("LoadDomainKeyPair failed: %v", err)
	}
	if loaded.Domain != dkp.Domain {
		t.Fatalf("domain mismatch: %s vs %s", loaded.Domain, dkp.Domain)
	}
	if !bytes.Equal(loaded.PublicKey, dkp.PublicKey) {
		t.Fatal("public key mismatch")
	}
	if !bytes.Equal(loaded.PrivateKey, dkp.PrivateKey) {
		t.Fatal("private key mismatch")
	}

	// Error paths
	var nilDKP *DomainKeyPair
	if err := nilDKP.SaveToFile(filePath); err == nil {
		t.Fatal("expected error on nil SaveToFile")
	}
	if _, err := LoadDomainKeyPair(filepath.Join(tempDir, "nonexistent.json")); err == nil {
		t.Fatal("expected error loading nonexistent file")
	}
	badFile := filepath.Join(tempDir, "bad.json")
	_ = os.WriteFile(badFile, []byte("bad json"), 0600)
	if _, err := LoadDomainKeyPair(badFile); err == nil {
		t.Fatal("expected error loading corrupt JSON")
	}
}

func TestKeyManager_InMemory(t *testing.T) {
	km, err := NewKeyManager("")
	if err != nil {
		t.Fatal(err)
	}

	// Generate
	dkp, err := km.Generate("my-domain.com")
	if err != nil {
		t.Fatalf("km.Generate failed: %v", err)
	}

	// Get & Load
	got, ok := km.Get("MY-DOMAIN.COM.")
	if !ok || got != dkp {
		t.Fatal("failed to get domain key")
	}
	loaded, err := km.Load("my-domain.com")
	if err != nil || loaded != dkp {
		t.Fatal("failed to load domain key")
	}

	// Sign
	msg := []byte("hello registry")
	sig, err := km.Sign("my-domain.com", msg)
	if err != nil {
		t.Fatalf("km.Sign failed: %v", err)
	}
	if err := dkp.Verify(msg, sig); err != nil {
		t.Fatal(err)
	}

	// Non-existent sign
	if _, err := km.Sign("unknown.com", msg); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}

	// Add
	other, _ := GenerateDomainKeyPair("added.org")
	if err := km.Add(other); err != nil {
		t.Fatal(err)
	}

	// ListDomains
	domains := km.ListDomains()
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}

	// Delete
	if err := km.Delete("added.org"); err != nil {
		t.Fatal(err)
	}
	if _, ok := km.Get("added.org"); ok {
		t.Fatal("expected added.org to be deleted")
	}
}

func TestKeyManager_FilesystemPersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "km_fs_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	km1, err := NewKeyManager(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	dkp1, err := km1.Generate("domain1.org")
	if err != nil {
		t.Fatal(err)
	}
	_ = dkp1

	// New manager pointing to same baseDir
	km2, err := NewKeyManager(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := km2.Load("domain1.org")
	if err != nil {
		t.Fatalf("failed to load persisted domain from disk: %v", err)
	}
	if loaded.Domain != "domain1.org" {
		t.Fatalf("domain mismatch: %s", loaded.Domain)
	}

	domains := km2.ListDomains()
	if len(domains) != 1 || domains[0] != "domain1.org" {
		t.Fatalf("unexpected domains: %v", domains)
	}

	// Delete from disk
	if err := km2.Delete("domain1.org"); err != nil {
		t.Fatal(err)
	}
	if _, err := km2.Load("domain1.org"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after delete, got %v", err)
	}
}

func TestKeyManager_ValidationAndConcurrency(t *testing.T) {
	km, _ := NewKeyManager("")

	// Invalid domains
	if _, err := km.Generate("bad/domain"); !errors.Is(err, ErrInvalidDomain) {
		t.Fatal("expected ErrInvalidDomain on Generate")
	}
	if err := km.Save(&DomainKeyPair{Domain: "bad/domain"}); !errors.Is(err, ErrInvalidDomain) {
		t.Fatal("expected ErrInvalidDomain on Save")
	}
	if _, err := km.Load("bad/domain"); !errors.Is(err, ErrInvalidDomain) {
		t.Fatal("expected ErrInvalidDomain on Load")
	}
	if err := km.Add(&DomainKeyPair{Domain: "bad/domain"}); !errors.Is(err, ErrInvalidDomain) {
		t.Fatal("expected ErrInvalidDomain on Add")
	}
	if err := km.Delete("bad/domain"); !errors.Is(err, ErrInvalidDomain) {
		t.Fatal("expected ErrInvalidDomain on Delete")
	}

	// Nil arguments
	if err := km.Save(nil); err == nil {
		t.Fatal("expected error saving nil")
	}
	if err := km.Add(nil); err == nil {
		t.Fatal("expected error adding nil")
	}

	// Concurrency
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			d := fmt.Sprintf("concurrent%d.com", id)
			pair, err := km.Generate(d)
			if err == nil {
				_, _ = km.Get(d)
				_, _ = km.Load(d)
				_ = km.ListDomains()
				_, _ = km.Sign(d, []byte("data"))
				_ = km.Delete(d)
				_ = km.Add(pair)
			}
		}(i)
	}
	wg.Wait()
}
