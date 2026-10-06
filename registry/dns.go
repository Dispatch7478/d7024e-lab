package registry

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// DefaultDNSTXTPrefix is the default DNS TXT record prefix for domain ownership.
const DefaultDNSTXTPrefix = "kademlia-pk="

var (
	ErrEmptyDomain      = errors.New("domain name cannot be empty")
	ErrDomainNotFound   = errors.New("domain not found")
	ErrNoOwnerKeyRecord = errors.New("no ownership record found in DNS TXT records")
	ErrInvalidOwnerKey  = errors.New("invalid public key in DNS ownership record")
)

type DNSResolver interface {
	LookupOwnerKey(domain string) (ed25519.PublicKey, error)
}

func NormalizeDomain(domain string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func FormatDNSTXTRecord(pub ed25519.PublicKey) string {
	return DefaultDNSTXTPrefix + EncodePublicKeyHex(pub)
}

type MockDNSResolver struct {
	mu      sync.RWMutex
	records map[string]ed25519.PublicKey
}

func NewMockDNSResolver() *MockDNSResolver {
	return &MockDNSResolver{records: make(map[string]ed25519.PublicKey)}
}

func (m *MockDNSResolver) SetKey(domain string, pub ed25519.PublicKey) error {
	norm := NormalizeDomain(domain)
	if norm == "" {
		return ErrEmptyDomain
	}
	if !IsValidDomain(norm) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[norm] = pub
	return nil
}

func (m *MockDNSResolver) SetKeyHex(domain, hexKey string) error {
	pub, err := DecodePublicKeyHex(hexKey)
	if err != nil {
		return err
	}
	return m.SetKey(domain, pub)
}

func (m *MockDNSResolver) RemoveKey(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, NormalizeDomain(domain))
}

func (m *MockDNSResolver) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = make(map[string]ed25519.PublicKey)
}

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

func (m *MockDNSResolver) LookupOwnerKey(domain string) (ed25519.PublicKey, error) {
	norm := NormalizeDomain(domain)
	if norm == "" {
		return nil, ErrEmptyDomain
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, ok := m.records[norm]
	if !ok {
		return nil, fmt.Errorf("%w: domain %q", ErrDomainNotFound, domain)
	}
	return key, nil
}

type SystemDNSResolver struct {
	lookupTXT func(name string) ([]string, error)
}

func NewSystemDNSResolver() *SystemDNSResolver {
	return &SystemDNSResolver{lookupTXT: net.LookupTXT}
}

func (s *SystemDNSResolver) LookupOwnerKey(domain string) (ed25519.PublicKey, error) {
	norm := NormalizeDomain(domain)
	if norm == "" {
		return nil, ErrEmptyDomain
	}
	records, err := s.lookupTXT(norm)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDomainNotFound, err)
	}
	return ParseOwnerKeyFromTXTRecords(records, DefaultDNSTXTPrefix)
}

func ParseOwnerKeyFromTXTRecords(records []string, prefix string) (ed25519.PublicKey, error) {
	if prefix == "" {
		prefix = DefaultDNSTXTPrefix
	}
	for _, record := range records {
		for _, part := range strings.Split(strings.Trim(strings.TrimSpace(record), "\"'"), ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), strings.ToLower(prefix)) {
				pub, err := DecodePublicKeyHex(strings.TrimSpace(part[len(prefix):]))
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrInvalidOwnerKey, err)
				}
				return pub, nil
			}
		}
	}
	return nil, ErrNoOwnerKeyRecord
}
