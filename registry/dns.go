package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultDNSTXTPrefix is the default DNS TXT record prefix for package registry domain ownership.
const DefaultDNSTXTPrefix = "kademlia-pk="

// DefaultDNSLookupTimeout is the default timeout applied to DNS TXT record queries.
const DefaultDNSLookupTimeout = 5 * time.Second

var (
	// ErrEmptyDomain is returned when an empty domain name is queried.
	ErrEmptyDomain = errors.New("domain name cannot be empty")
	// ErrDomainNotFound is returned when the domain cannot be resolved via DNS.
	ErrDomainNotFound = errors.New("domain not found")
	// ErrNoOwnerKeyRecord is returned when DNS TXT records exist for the domain, but none match the ownership prefix.
	ErrNoOwnerKeyRecord = errors.New("no ownership record found in DNS TXT records")
	// ErrInvalidOwnerKey is returned when the DNS ownership record value contains an invalid public key.
	ErrInvalidOwnerKey = errors.New("invalid public key in DNS ownership record")
	// ErrMultipleOwnerKeys is returned when DNS records contain conflicting ownership public keys.
	ErrMultipleOwnerKeys = errors.New("conflicting owner public keys in DNS records")
)

// DNSResolver represents an oracle capable of resolving the Ed25519 owner public key for a domain.
type DNSResolver interface {
	LookupOwnerKey(domain string) (ed25519.PublicKey, error)
}

// NormalizeDomain trims whitespace, lowercases, and strips any trailing root dot.
func NormalizeDomain(domain string) string {
	d := strings.TrimSpace(domain)
	d = strings.ToLower(d)
	d = strings.TrimRight(d, ".")
	return d
}

// FormatDNSTXTRecord formats an Ed25519 public key as a DNS TXT record value using DefaultDNSTXTPrefix.
func FormatDNSTXTRecord(pub ed25519.PublicKey) string {
	return DefaultDNSTXTPrefix + EncodePublicKeyHex(pub)
}

// FormatDNSTXTRecordWithPrefix formats a public key with a custom prefix.
func FormatDNSTXTRecordWithPrefix(prefix string, pub ed25519.PublicKey) string {
	return prefix + EncodePublicKeyHex(pub)
}

// MockDNSResolver is a thread-safe in-memory implementation of DNSResolver.
// Useful for unit tests, simulated networks, and development environments.
type MockDNSResolver struct {
	mu      sync.RWMutex
	records map[string]ed25519.PublicKey
}

// NewMockDNSResolver creates a new empty MockDNSResolver.
func NewMockDNSResolver() *MockDNSResolver {
	return &MockDNSResolver{
		records: make(map[string]ed25519.PublicKey),
	}
}

// SetKey maps a domain to an Ed25519 public key.
func (m *MockDNSResolver) SetKey(domain string, pub ed25519.PublicKey) error {
	norm := NormalizeDomain(domain)
	if norm == "" {
		return ErrEmptyDomain
	}
	if !IsValidDomain(norm) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidPublicKeySize, len(pub))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	keyCopy := make(ed25519.PublicKey, len(pub))
	copy(keyCopy, pub)
	m.records[norm] = keyCopy
	return nil
}

// SetKeyHex decodes a hex string and maps the domain to the decoded public key.
func (m *MockDNSResolver) SetKeyHex(domain string, hexKey string) error {
	pub, err := DecodePublicKeyHex(hexKey)
	if err != nil {
		return err
	}
	return m.SetKey(domain, pub)
}

// SetKeyBase64 decodes a base64 string and maps the domain to the decoded public key.
func (m *MockDNSResolver) SetKeyBase64(domain string, b64Key string) error {
	pub, err := DecodePublicKeyBase64(b64Key)
	if err != nil {
		return err
	}
	return m.SetKey(domain, pub)
}

// RemoveKey removes any mapping for the specified domain.
func (m *MockDNSResolver) RemoveKey(domain string) {
	norm := NormalizeDomain(domain)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, norm)
}

// Clear removes all domain mappings.
func (m *MockDNSResolver) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = make(map[string]ed25519.PublicKey)
}

// ListDomains returns a sorted slice of all domains currently registered in the resolver.
func (m *MockDNSResolver) ListDomains() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	domains := make([]string, 0, len(m.records))
	for d := range m.records {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}

// LookupOwnerKey implements DNSResolver for MockDNSResolver.
func (m *MockDNSResolver) LookupOwnerKey(domain string) (ed25519.PublicKey, error) {
	norm := NormalizeDomain(domain)
	if norm == "" {
		return nil, ErrEmptyDomain
	}
	if !IsValidDomain(norm) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, exists := m.records[norm]
	if !exists {
		return nil, fmt.Errorf("%w: domain %q", ErrDomainNotFound, domain)
	}
	keyCopy := make(ed25519.PublicKey, len(key))
	copy(keyCopy, key)
	return keyCopy, nil
}

// TXTLookupFunc is the signature of functions that query DNS TXT records.
type TXTLookupFunc func(name string) ([]string, error)

// SystemDNSResolver queries DNS TXT records using the system DNS resolver or custom nameserver.
type SystemDNSResolver struct {
	lookupTXT TXTLookupFunc
	prefix    string
	timeout   time.Duration
}

// NewSystemDNSResolver creates a SystemDNSResolver using standard net.LookupTXT and DefaultDNSTXTPrefix.
func NewSystemDNSResolver() *SystemDNSResolver {
	return NewSystemDNSResolverWithTimeout(DefaultDNSLookupTimeout)
}

// NewSystemDNSResolverWithTimeout creates a SystemDNSResolver with a query timeout.
func NewSystemDNSResolverWithTimeout(timeout time.Duration) *SystemDNSResolver {
	if timeout <= 0 {
		timeout = DefaultDNSLookupTimeout
	}
	lookupFn := func(name string) ([]string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return net.DefaultResolver.LookupTXT(ctx, name)
	}
	return &SystemDNSResolver{
		lookupTXT: lookupFn,
		prefix:    DefaultDNSTXTPrefix,
		timeout:   timeout,
	}
}

// NewCustomSystemDNSResolver creates a SystemDNSResolver with a custom lookup function and prefix.
func NewCustomSystemDNSResolver(fn TXTLookupFunc, prefix string) *SystemDNSResolver {
	if fn == nil {
		fn = net.LookupTXT
	}
	if prefix == "" {
		prefix = DefaultDNSTXTPrefix
	}
	return &SystemDNSResolver{
		lookupTXT: fn,
		prefix:    prefix,
		timeout:   DefaultDNSLookupTimeout,
	}
}

// NewSystemDNSResolverWithConfig creates a SystemDNSResolver with custom nameserver, timeout, and prefix.
// If nameserver is empty, system default resolver is used.
func NewSystemDNSResolverWithConfig(nameserver string, timeout time.Duration, prefix string) *SystemDNSResolver {
	if timeout <= 0 {
		timeout = DefaultDNSLookupTimeout
	}
	if prefix == "" {
		prefix = DefaultDNSTXTPrefix
	}

	var resolver *net.Resolver
	if nameserver != "" {
		ns := nameserver
		if !strings.Contains(ns, ":") {
			ns = net.JoinHostPort(ns, "53")
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "udp", ns)
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	lookupFn := func(name string) ([]string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return resolver.LookupTXT(ctx, name)
	}

	return &SystemDNSResolver{
		lookupTXT: lookupFn,
		prefix:    prefix,
		timeout:   timeout,
	}
}

// LookupOwnerKey queries the domain's TXT records and parses the kademlia-pk ownership public key.
func (s *SystemDNSResolver) LookupOwnerKey(domain string) (ed25519.PublicKey, error) {
	norm := NormalizeDomain(domain)
	if norm == "" {
		return nil, ErrEmptyDomain
	}
	if !IsValidDomain(norm) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	records, err := s.lookupTXT(norm)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDomainNotFound, err)
	}
	return ParseOwnerKeyFromTXTRecords(records, s.prefix)
}

// ParseOwnerKeyFromTXTRecords parses a slice of DNS TXT records and extracts the Ed25519 owner public key.
// It handles quoted records, case-insensitive prefixes, optional whitespace around '=',
// semicolon-delimited multi-attribute records, and validates consistency if multiple records exist.
func ParseOwnerKeyFromTXTRecords(records []string, prefix string) (ed25519.PublicKey, error) {
	if prefix == "" {
		prefix = DefaultDNSTXTPrefix
	}
	prefixLower := strings.ToLower(prefix)
	prefixNoEq := strings.TrimSuffix(prefixLower, "=")

	var matchedKeys []ed25519.PublicKey

	for _, record := range records {
		cleanRecord := strings.Trim(strings.TrimSpace(record), "\"'")
		directives := strings.Split(cleanRecord, ";")

		for _, dir := range directives {
			clean := strings.Trim(strings.TrimSpace(dir), "\"'")
			if clean == "" {
				continue
			}
			cleanLower := strings.ToLower(clean)
			var val string

			if strings.HasPrefix(cleanLower, prefixLower) {
				val = strings.TrimSpace(clean[len(prefix):])
			} else if strings.HasPrefix(cleanLower, prefixNoEq) {
				rest := strings.TrimSpace(clean[len(prefixNoEq):])
				if strings.HasPrefix(rest, "=") {
					val = strings.TrimSpace(rest[1:])
				} else {
					continue
				}
			} else {
				continue
			}

			val = strings.Trim(val, "\"'")
			pub, err := ParsePublicKey(val)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidOwnerKey, err)
			}
			matchedKeys = append(matchedKeys, pub)
		}
	}

	if len(matchedKeys) == 0 {
		return nil, ErrNoOwnerKeyRecord
	}

	// Verify all matching records agree on the same public key
	first := matchedKeys[0]
	for i := 1; i < len(matchedKeys); i++ {
		if !bytes.Equal(first, matchedKeys[i]) {
			return nil, fmt.Errorf("%w: found distinct keys %x and %x", ErrMultipleOwnerKeys, first, matchedKeys[i])
		}
	}

	keyCopy := make(ed25519.PublicKey, len(first))
	copy(keyCopy, first)
	return keyCopy, nil
}
