package registry

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
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
		{"   ", ""},
	}

	for _, c := range cases {
		got := NormalizeDomain(c.input)
		if got != c.expected {
			t.Errorf("NormalizeDomain(%q) = %q; want %q", c.input, got, c.expected)
		}
	}
}

func TestFormatDNSTXTRecord(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rec := FormatDNSTXTRecord(pub)
	expectedPrefix := "kademlia-pk="
	if len(rec) <= len(expectedPrefix) || rec[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("expected record to start with %q, got %q", expectedPrefix, rec)
	}

	extractedHex := rec[len(expectedPrefix):]
	decPub, err := DecodePublicKeyHex(extractedHex)
	if err != nil || !bytes.Equal(pub, decPub) {
		t.Errorf("extracted hex key mismatch: %v", err)
	}

	custom := FormatDNSTXTRecordWithPrefix("custom-pk=", pub)
	if custom != "custom-pk="+EncodePublicKeyHex(pub) {
		t.Errorf("custom prefix record mismatch: got %q", custom)
	}
}

func TestMockDNSResolver_Basic(t *testing.T) {
	resolver := NewMockDNSResolver()
	pub, _, _ := GenerateKeyPair()

	// Empty domain errors
	if err := resolver.SetKey("", pub); !errors.Is(err, ErrEmptyDomain) {
		t.Errorf("expected ErrEmptyDomain on SetKey, got %v", err)
	}
	if _, err := resolver.LookupOwnerKey(""); !errors.Is(err, ErrEmptyDomain) {
		t.Errorf("expected ErrEmptyDomain on LookupOwnerKey, got %v", err)
	}

	// Invalid pub key size
	if err := resolver.SetKey("example.com", pub[:16]); !errors.Is(err, ErrInvalidPublicKeySize) {
		t.Errorf("expected ErrInvalidPublicKeySize, got %v", err)
	}

	// Register key
	if err := resolver.SetKey("Example.COM.", pub); err != nil {
		t.Fatalf("failed to SetKey: %v", err)
	}

	// Lookup normalized domain
	resolved, err := resolver.LookupOwnerKey("example.com")
	if err != nil {
		t.Fatalf("failed to lookup owner key: %v", err)
	}
	if !bytes.Equal(pub, resolved) {
		t.Errorf("resolved key does not match registered key")
	}

	// Defensive copy verification
	resolved[0] ^= 0xFF
	resolvedAgain, _ := resolver.LookupOwnerKey("example.com")
	if bytes.Equal(resolved, resolvedAgain) {
		t.Errorf("MockDNSResolver leaked mutable reference to internal key")
	}

	// Nonexistent domain
	if _, err := resolver.LookupOwnerKey("notfound.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}

	// Remove key
	resolver.RemoveKey("EXAMPLE.com.")
	if _, err := resolver.LookupOwnerKey("example.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound after RemoveKey, got %v", err)
	}
}

func TestMockDNSResolver_SetKeyHex(t *testing.T) {
	resolver := NewMockDNSResolver()
	pub, _, _ := GenerateKeyPair()
	hexKey := EncodePublicKeyHex(pub)

	if err := resolver.SetKeyHex("foo.org", hexKey); err != nil {
		t.Fatalf("failed to SetKeyHex: %v", err)
	}
	resolved, err := resolver.LookupOwnerKey("foo.org")
	if err != nil || !bytes.Equal(pub, resolved) {
		t.Errorf("lookup after SetKeyHex failed: %v", err)
	}

	if err := resolver.SetKeyHex("bar.org", "invalid-hex"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding for invalid hex, got %v", err)
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
			resolver.RemoveKey(domain)
		}(i)
	}
	wg.Wait()
}

func TestSystemDNSResolver(t *testing.T) {
	pub1, _, _ := GenerateKeyPair()
	pub2, _, _ := GenerateKeyPair()

	tests := []struct {
		name        string
		records     []string
		lookupErr   error
		domain      string
		expectedPub ed25519.PublicKey
		expectedErr error
	}{
		{
			name:        "Empty domain query",
			domain:      "",
			expectedErr: ErrEmptyDomain,
		},
		{
			name:        "DNS lookup network failure",
			domain:      "error.com",
			lookupErr:   errors.New("no such host"),
			expectedErr: ErrDomainNotFound,
		},
		{
			name:        "Valid hex record",
			domain:      "valid-hex.com",
			records:     []string{"kademlia-pk=" + EncodePublicKeyHex(pub1)},
			expectedPub: pub1,
		},
		{
			name:        "Valid record with surrounding quotes",
			domain:      "quoted.com",
			records:     []string{"\"kademlia-pk=" + EncodePublicKeyHex(pub1) + "\""},
			expectedPub: pub1,
		},
		{
			name:        "Valid base64 record",
			domain:      "valid-b64.com",
			records:     []string{"kademlia-pk=" + EncodePublicKeyBase64(pub1)},
			expectedPub: pub1,
		},
		{
			name:        "Mixed case prefix",
			domain:      "mixed-case.com",
			records:     []string{"KADEMLIA-PK=" + EncodePublicKeyHex(pub1)},
			expectedPub: pub1,
		},
		{
			name:   "Multiple TXT records with other unrelated entries",
			domain: "multi.com",
			records: []string{
				"v=spf1 include:_spf.google.com ~all",
				"some-unrelated-verification-token",
				"kademlia-pk=" + EncodePublicKeyHex(pub1),
			},
			expectedPub: pub1,
		},
		{
			name:   "Multiple identical ownership records",
			domain: "identical.com",
			records: []string{
				"kademlia-pk=" + EncodePublicKeyHex(pub1),
				"kademlia-pk=" + EncodePublicKeyHex(pub1),
			},
			expectedPub: pub1,
		},
		{
			name:   "Conflicting distinct ownership records",
			domain: "conflict.com",
			records: []string{
				"kademlia-pk=" + EncodePublicKeyHex(pub1),
				"kademlia-pk=" + EncodePublicKeyHex(pub2),
			},
			expectedErr: ErrMultipleOwnerKeys,
		},
		{
			name:        "No matching kademlia-pk records",
			domain:      "no-pk.com",
			records:     []string{"v=spf1 ~all", "google-site-verification=abc"},
			expectedErr: ErrNoOwnerKeyRecord,
		},
		{
			name:        "Malformed public key in record",
			domain:      "bad-key.com",
			records:     []string{"kademlia-pk=not-a-valid-key"},
			expectedErr: ErrInvalidOwnerKey,
		},
		{
			name:        "Semicolon-delimited directives in single record",
			domain:      "semi.com",
			records:     []string{"v=d7024e; kademlia-pk=" + EncodePublicKeyHex(pub1) + "; status=active"},
			expectedPub: pub1,
		},
		{
			name:        "Trailing semicolon in single record",
			domain:      "trailing-semi.com",
			records:     []string{"kademlia-pk=" + EncodePublicKeyHex(pub1) + ";"},
			expectedPub: pub1,
		},
		{
			name:        "Spaces around equals",
			domain:      "spaces-eq.com",
			records:     []string{"kademlia-pk = " + EncodePublicKeyHex(pub1)},
			expectedPub: pub1,
		},
		{
			name:        "Single-quoted record",
			domain:      "single-quoted.com",
			records:     []string{"'kademlia-pk=" + EncodePublicKeyHex(pub1) + "'"},
			expectedPub: pub1,
		},
		{
			name:        "0x-prefixed hex record",
			domain:      "0x-hex.com",
			records:     []string{"kademlia-pk=0x" + EncodePublicKeyHex(pub1)},
			expectedPub: pub1,
		},
		{
			name:        "Invalid domain syntax",
			domain:      "../invalid/domain",
			records:     []string{"kademlia-pk=" + EncodePublicKeyHex(pub1)},
			expectedErr: ErrInvalidDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			customLookup := func(name string) ([]string, error) {
				if tt.lookupErr != nil {
					return nil, tt.lookupErr
				}
				return tt.records, nil
			}

			resolver := NewCustomSystemDNSResolver(customLookup, DefaultDNSTXTPrefix)
			got, err := resolver.LookupOwnerKey(tt.domain)

			if tt.expectedErr != nil {
				if !errors.Is(err, tt.expectedErr) {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !bytes.Equal(got, tt.expectedPub) {
					t.Errorf("got pubkey %x, want %x", got, tt.expectedPub)
				}
			}
		})
	}
}

func TestSystemDNSResolver_ConstructorsAndPrefix(t *testing.T) {
	pub, _, _ := GenerateKeyPair()

	// Default constructor NewSystemDNSResolver
	defaultResolver := NewSystemDNSResolver()
	if defaultResolver == nil || defaultResolver.lookupTXT == nil || defaultResolver.prefix != DefaultDNSTXTPrefix {
		t.Fatal("NewSystemDNSResolver failed to initialize properly")
	}

	// Custom prefix
	customResolver := NewCustomSystemDNSResolver(func(name string) ([]string, error) {
		return []string{"pkg-reg-key=" + EncodePublicKeyHex(pub)}, nil
	}, "pkg-reg-key=")

	resolved, err := customResolver.LookupOwnerKey("my-domain.org")
	if err != nil {
		t.Fatalf("failed custom prefix lookup: %v", err)
	}
	if !bytes.Equal(pub, resolved) {
		t.Errorf("custom prefix resolved key mismatch")
	}

	// Fallback to defaults when empty arguments passed to NewCustomSystemDNSResolver
	emptyArgsResolver := NewCustomSystemDNSResolver(nil, "")
	if emptyArgsResolver.prefix != DefaultDNSTXTPrefix || emptyArgsResolver.lookupTXT == nil {
		t.Errorf("NewCustomSystemDNSResolver with nil/empty did not set defaults")
	}

	// Timeout constructor
	timeoutResolver := NewSystemDNSResolverWithTimeout(2 * time.Second)
	if timeoutResolver.timeout != 2*time.Second {
		t.Errorf("expected timeout 2s, got %v", timeoutResolver.timeout)
	}

	// Config constructor with custom nameserver
	cfgResolver := NewSystemDNSResolverWithConfig("127.0.0.1:53", 1*time.Second, "my-pk=")
	if cfgResolver.prefix != "my-pk=" || cfgResolver.timeout != 1*time.Second {
		t.Errorf("expected prefix 'my-pk=' and 1s timeout, got %s, %v", cfgResolver.prefix, cfgResolver.timeout)
	}

	// Config constructor with nameserver without port
	cfgResolver2 := NewSystemDNSResolverWithConfig("127.0.0.1", 0, "")
	if cfgResolver2.prefix != DefaultDNSTXTPrefix || cfgResolver2.timeout != DefaultDNSLookupTimeout {
		t.Errorf("expected default prefix and timeout for empty/0 values")
	}
}

func TestMockDNSResolver_DomainValidation(t *testing.T) {
	resolver := NewMockDNSResolver()
	pub, _, _ := GenerateKeyPair()

	if err := resolver.SetKey("../evil", pub); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain on SetKey with traversal path, got %v", err)
	}
	if _, err := resolver.LookupOwnerKey("invalid/domain"); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain on LookupOwnerKey with slashes, got %v", err)
	}
}

func TestMockDNSResolver_SetKeyBase64(t *testing.T) {
	resolver := NewMockDNSResolver()
	pub, _, _ := GenerateKeyPair()
	b64 := EncodePublicKeyBase64(pub)

	if err := resolver.SetKeyBase64("b64-domain.com", b64); err != nil {
		t.Fatalf("SetKeyBase64 failed: %v", err)
	}
	resolved, err := resolver.LookupOwnerKey("b64-domain.com")
	if err != nil || !bytes.Equal(pub, resolved) {
		t.Errorf("lookup after SetKeyBase64 failed: %v", err)
	}

	if err := resolver.SetKeyBase64("bad.com", "not!base64!"); !errors.Is(err, ErrInvalidEncoding) {
		t.Errorf("expected ErrInvalidEncoding, got %v", err)
	}
}

func TestMockDNSResolver_ListDomainsAndClear(t *testing.T) {
	resolver := NewMockDNSResolver()
	pub, _, _ := GenerateKeyPair()

	_ = resolver.SetKey("zeta.com", pub)
	_ = resolver.SetKey("alpha.com", pub)
	_ = resolver.SetKey("beta.com", pub)

	domains := resolver.ListDomains()
	if len(domains) != 3 {
		t.Fatalf("expected 3 domains, got %d", len(domains))
	}
	// Verify sorted order
	if domains[0] != "alpha.com" || domains[1] != "beta.com" || domains[2] != "zeta.com" {
		t.Errorf("expected sorted domains [alpha.com beta.com zeta.com], got %v", domains)
	}

	resolver.Clear()
	if len(resolver.ListDomains()) != 0 {
		t.Errorf("expected empty domains after Clear()")
	}
}
