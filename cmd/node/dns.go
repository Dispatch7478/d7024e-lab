package main

import (
	"crypto/ed25519"
	"d7024e/registry"
	"fmt"
	"sync"
)

// NodeDNSResolver provides domain ownership resolution by checking local/mock records
// first and optionally delegating to system DNS when available.
type NodeDNSResolver struct {
	mu     sync.RWMutex
	mock   *registry.MockDNSResolver
	system *registry.SystemDNSResolver
	km     *registry.KeyManager
}

// NewNodeDNSResolver constructs a NodeDNSResolver.
func NewNodeDNSResolver() *NodeDNSResolver {
	return &NodeDNSResolver{
		mock:   registry.NewMockDNSResolver(),
		system: registry.NewSystemDNSResolver(),
	}
}

// SetKeyManager sets the KeyManager to check for domain keys.
func (r *NodeDNSResolver) SetKeyManager(km *registry.KeyManager) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.km = km
}

// LookupOwnerKey implements registry.DNSResolver.
func (r *NodeDNSResolver) LookupOwnerKey(domain string) (ed25519.PublicKey, error) {
	norm := registry.NormalizeDomain(domain)
	if norm == "" {
		return nil, registry.ErrEmptyDomain
	}

	r.mu.RLock()
	mock := r.mock
	system := r.system
	km := r.km
	r.mu.RUnlock()

	// Check KeyManager first (fresh read from disk if domain key exists)
	if km != nil {
		dkp, err := km.Load(norm)
		if err == nil && dkp != nil && len(dkp.PublicKey) == ed25519.PublicKeySize {
			if mock != nil {
				_ = mock.SetKey(norm, dkp.PublicKey)
			}
			return dkp.PublicKey, nil
		}
	}

	// Check local mock registry (e.g. set via 'set dns')
	if mock != nil {
		pub, err := mock.LookupOwnerKey(norm)
		if err == nil && len(pub) == ed25519.PublicKeySize {
			return pub, nil
		}
	}

	// Fall back to system DNS
	if system != nil {
		pub, err := system.LookupOwnerKey(norm)
		if err == nil && len(pub) == ed25519.PublicKeySize {
			return pub, nil
		}
	}

	return nil, fmt.Errorf("%w: %q", registry.ErrDomainNotFound, domain)
}

// SetKey maps a domain to an Ed25519 public key in the local resolver cache.
func (r *NodeDNSResolver) SetKey(domain string, pub ed25519.PublicKey) error {
	r.mu.Lock()
	if r.mock == nil {
		r.mock = registry.NewMockDNSResolver()
	}
	mock := r.mock
	r.mu.Unlock()
	return mock.SetKey(domain, pub)
}

// SetKeyHex decodes a hex string and maps the domain in the local resolver cache.
func (r *NodeDNSResolver) SetKeyHex(domain string, hexKey string) error {
	r.mu.Lock()
	if r.mock == nil {
		r.mock = registry.NewMockDNSResolver()
	}
	mock := r.mock
	r.mu.Unlock()
	return mock.SetKeyHex(domain, hexKey)
}

// ListDomains returns all domains registered in the local resolver cache.
func (r *NodeDNSResolver) ListDomains() []string {
	r.mu.RLock()
	mock := r.mock
	r.mu.RUnlock()
	if mock == nil {
		return nil
	}
	return mock.ListDomains()
}
