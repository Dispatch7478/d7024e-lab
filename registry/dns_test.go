package registry

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"example.com.", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"  Example.COM.  ", "example.com"},
		{"sub.domain.org...", "sub.domain.org"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeDomain(c.input); got != c.expected {
			t.Errorf("NormalizeDomain(%q) = %q; want %q", c.input, got, c.expected)
		}
	}
}

func TestFormatDNSTXTRecord(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec := FormatDNSTXTRecord(pub)
	if rec != DefaultDNSTXTPrefix+EncodePublicKeyHex(pub) {
		t.Fatalf("unexpected TXT record format: %s", rec)
	}
}

func TestMockDNSResolver(t *testing.T) {
	resolver := NewMockDNSResolver()
	pub, _, _ := GenerateKeyPair()

	// Empty domain
	if err := resolver.SetKey("", pub); !errors.Is(err, ErrEmptyDomain) {
		t.Fatalf("expected ErrEmptyDomain on SetKey, got %v", err)
	}
	if _, err := resolver.LookupOwnerKey(""); !errors.Is(err, ErrEmptyDomain) {
		t.Fatalf("expected ErrEmptyDomain on LookupOwnerKey, got %v", err)
	}

	// Register key
	if err := resolver.SetKey("example.com", pub); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	// Lookup
	resolved, err := resolver.LookupOwnerKey("EXAMPLE.COM.")
	if err != nil || !bytes.Equal(pub, resolved) {
		t.Fatalf("LookupOwnerKey failed or mismatch: %v", err)
	}

	// SetKeyHex
	hexKey := EncodePublicKeyHex(pub)
	if err := resolver.SetKeyHex("hex-domain.com", hexKey); err != nil {
		t.Fatalf("SetKeyHex failed: %v", err)
	}
	if _, err := resolver.LookupOwnerKey("hex-domain.com"); err != nil {
		t.Fatalf("LookupOwnerKey after SetKeyHex failed: %v", err)
	}
	if err := resolver.SetKeyHex("bad.com", "not-hex"); err == nil {
		t.Fatal("expected error on invalid hex key")
	}

	// ListDomains
	domains := resolver.ListDomains()
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}

	// RemoveKey
	resolver.RemoveKey("example.com")
	if _, err := resolver.LookupOwnerKey("example.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("expected ErrDomainNotFound after RemoveKey, got %v", err)
	}

	// Clear
	resolver.Clear()
	if len(resolver.ListDomains()) != 0 {
		t.Fatal("expected 0 domains after Clear")
	}
}

func TestMockDNSResolver_Concurrency(t *testing.T) {
	resolver := NewMockDNSResolver()
	pub, _, _ := GenerateKeyPair()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			domain := fmt.Sprintf("domain%d.com", id)
			_ = resolver.SetKey(domain, pub)
			_, _ = resolver.LookupOwnerKey(domain)
			_ = resolver.ListDomains()
			resolver.RemoveKey(domain)
		}(i)
	}
	wg.Wait()
}

func TestSystemDNSResolver_And_ParseTXT(t *testing.T) {
	pub, _, _ := GenerateKeyPair()
	hexKey := EncodePublicKeyHex(pub)

	// Valid TXT record
	sys := &SystemDNSResolver{
		lookupTXT: func(name string) ([]string, error) {
			return []string{"kademlia-pk=" + hexKey}, nil
		},
	}
	resPub, err := sys.LookupOwnerKey("example.com")
	if err != nil || !bytes.Equal(pub, resPub) {
		t.Fatalf("SystemDNSResolver.LookupOwnerKey failed: %v", err)
	}

	// Lookup error
	sysErr := &SystemDNSResolver{
		lookupTXT: func(name string) ([]string, error) {
			return nil, errors.New("no host")
		},
	}
	if _, err := sysErr.LookupOwnerKey("example.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("expected ErrDomainNotFound, got %v", err)
	}

	// Empty domain
	if _, err := sys.LookupOwnerKey(""); !errors.Is(err, ErrEmptyDomain) {
		t.Fatalf("expected ErrEmptyDomain, got %v", err)
	}

	// ParseOwnerKeyFromTXTRecords with other TXT entries and semicolon
	records := []string{
		"v=spf1 ~all",
		"something-else; kademlia-pk=" + hexKey + "; note=ok",
	}
	parsedPub, err := ParseOwnerKeyFromTXTRecords(records, "")
	if err != nil || !bytes.Equal(pub, parsedPub) {
		t.Fatalf("ParseOwnerKeyFromTXTRecords failed: %v", err)
	}

	// No owner key record
	if _, err := ParseOwnerKeyFromTXTRecords([]string{"v=spf1 ~all"}, ""); !errors.Is(err, ErrNoOwnerKeyRecord) {
		t.Fatalf("expected ErrNoOwnerKeyRecord, got %v", err)
	}

	// Invalid owner key
	if _, err := ParseOwnerKeyFromTXTRecords([]string{"kademlia-pk=not-hex"}, ""); !errors.Is(err, ErrInvalidOwnerKey) {
		t.Fatalf("expected ErrInvalidOwnerKey, got %v", err)
	}

	// Standard constructor
	stdSys := NewSystemDNSResolver()
	if stdSys == nil || stdSys.lookupTXT == nil {
		t.Fatal("NewSystemDNSResolver failed")
	}
}
