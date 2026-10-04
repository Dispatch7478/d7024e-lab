package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrInvalidDomain indicates an invalid or malformed domain name.
	ErrInvalidDomain = errors.New("invalid domain name")
	// ErrKeyNotFound indicates the requested domain key was not found.
	ErrKeyNotFound = errors.New("domain key not found")
)

// domainNameRegex matches valid domain and host names conforming to RFC 1035 / RFC 1123.
var domainNameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// IsValidDomain checks whether a domain name is syntactically valid and free of path-traversal tokens.
func IsValidDomain(domain string) bool {
	norm := NormalizeDomain(domain)
	if norm == "" || len(norm) > 253 {
		return false
	}
	if strings.Contains(norm, "/") || strings.Contains(norm, "\\") || strings.Contains(norm, "..") {
		return false
	}
	return domainNameRegex.MatchString(norm)
}

// DomainKeyPair represents the Ed25519 cryptographic key pair associated with a domain identity.
type DomainKeyPair struct {
	Domain     string             `json:"domain"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
	CreatedAt  time.Time          `json:"created_at"`
}

type domainKeyPairJSON struct {
	Domain     string    `json:"domain"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"private_key"`
	CreatedAt  time.Time `json:"created_at"`
}

// NewDomainKeyPair constructs a DomainKeyPair from existing Ed25519 keys after validation.
// It verifies that the public key corresponds to the private key.
func NewDomainKeyPair(domain string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (*DomainKeyPair, error) {
	norm := NormalizeDomain(domain)
	if !IsValidDomain(norm) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPublicKeySize, len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPrivateKeySize, len(priv))
	}
	if !bytes.Equal(pub, priv[32:]) {
		return nil, fmt.Errorf("%w: public key does not match private key", ErrMismatchedKeyPair)
	}

	pubCopy := make(ed25519.PublicKey, len(pub))
	copy(pubCopy, pub)
	privCopy := make(ed25519.PrivateKey, len(priv))
	copy(privCopy, priv)

	return &DomainKeyPair{
		Domain:     norm,
		PublicKey:  pubCopy,
		PrivateKey: privCopy,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// GenerateDomainKeyPair creates a new random Ed25519 key pair for the given domain.
func GenerateDomainKeyPair(domain string) (*DomainKeyPair, error) {
	norm := NormalizeDomain(domain)
	if !IsValidDomain(norm) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &DomainKeyPair{
		Domain:     norm,
		PublicKey:  pub,
		PrivateKey: priv,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// Sign signs a message using the domain's private key.
func (dkp *DomainKeyPair) Sign(message []byte) ([]byte, error) {
	if dkp == nil {
		return nil, errors.New("domain key pair is nil")
	}
	return Sign(dkp.PrivateKey, message)
}

// Verify verifies a signature against a message using the domain's public key.
func (dkp *DomainKeyPair) Verify(message []byte, sig []byte) error {
	if dkp == nil {
		return errors.New("domain key pair is nil")
	}
	return Verify(dkp.PublicKey, message, sig)
}

// DNSTXTRecord returns the DNS TXT record value string for this domain's public key.
func (dkp *DomainKeyPair) DNSTXTRecord() string {
	if dkp == nil {
		return ""
	}
	return FormatDNSTXTRecord(dkp.PublicKey)
}

// PublicKeyHex returns the hexadecimal string encoding of the public key.
func (dkp *DomainKeyPair) PublicKeyHex() string {
	if dkp == nil {
		return ""
	}
	return EncodePublicKeyHex(dkp.PublicKey)
}

// PublicKeyBase64 returns the base64 string encoding of the public key.
func (dkp *DomainKeyPair) PublicKeyBase64() string {
	if dkp == nil {
		return ""
	}
	return EncodePublicKeyBase64(dkp.PublicKey)
}

// MarshalJSON marshals the DomainKeyPair with hex-encoded public and private keys.
func (dkp *DomainKeyPair) MarshalJSON() ([]byte, error) {
	if dkp == nil {
		return nil, errors.New("cannot marshal nil DomainKeyPair")
	}
	dto := domainKeyPairJSON{
		Domain:     dkp.Domain,
		PublicKey:  EncodePublicKeyHex(dkp.PublicKey),
		PrivateKey: EncodePrivateKeyHex(dkp.PrivateKey),
		CreatedAt:  dkp.CreatedAt,
	}
	return json.MarshalIndent(dto, "", "  ")
}

// UnmarshalJSON unmarshals the DomainKeyPair from JSON, accepting hex or base64 keys.
// Validates that the public key corresponds to the private key.
func (dkp *DomainKeyPair) UnmarshalJSON(data []byte) error {
	var dto domainKeyPairJSON
	if err := json.Unmarshal(data, &dto); err != nil {
		return err
	}
	norm := NormalizeDomain(dto.Domain)
	if !IsValidDomain(norm) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, dto.Domain)
	}
	pub, err := ParsePublicKey(dto.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key in JSON: %w", err)
	}
	priv, err := ParsePrivateKey(dto.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid private key in JSON: %w", err)
	}
	if !bytes.Equal(pub, priv[32:]) {
		return fmt.Errorf("%w: public key does not match private key in JSON", ErrMismatchedKeyPair)
	}
	dkp.Domain = norm
	dkp.PublicKey = pub
	dkp.PrivateKey = priv
	dkp.CreatedAt = dto.CreatedAt
	return nil
}

// SaveToFile writes the key pair to a JSON file with restricted owner permissions (0600).
func (dkp *DomainKeyPair) SaveToFile(filePath string) error {
	if dkp == nil {
		return errors.New("cannot save nil domain key pair")
	}
	data, err := json.MarshalIndent(dkp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain key pair: %w", err)
	}
	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file %s: %w", filePath, err)
	}
	if err := os.Chmod(filePath, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions %s: %w", filePath, err)
	}
	return nil
}

// LoadDomainKeyPair reads and deserializes a DomainKeyPair from a JSON file.
func LoadDomainKeyPair(filePath string) (*DomainKeyPair, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", filePath, err)
	}
	var dkp DomainKeyPair
	if err := json.Unmarshal(data, &dkp); err != nil {
		return nil, fmt.Errorf("failed to decode key file %s: %w", filePath, err)
	}
	return &dkp, nil
}

// KeyManager manages multiple domain keypairs in memory with optional filesystem persistence.
type KeyManager struct {
	mu      sync.RWMutex
	baseDir string
	keys    map[string]*DomainKeyPair
}

// NewKeyManager initializes a KeyManager. If baseDir is non-empty, the directory is created if needed.
func NewKeyManager(baseDir string) (*KeyManager, error) {
	if baseDir != "" {
		if err := os.MkdirAll(baseDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create key manager directory %s: %w", baseDir, err)
		}
	}
	return &KeyManager{
		baseDir: baseDir,
		keys:    make(map[string]*DomainKeyPair),
	}, nil
}

// Generate creates, caches, and persists an Ed25519 key pair for the specified domain.
func (km *KeyManager) Generate(domain string) (*DomainKeyPair, error) {
	dkp, err := GenerateDomainKeyPair(domain)
	if err != nil {
		return nil, err
	}
	if err := km.Save(dkp); err != nil {
		return nil, err
	}
	return dkp, nil
}

// Save caches the domain key pair in memory and writes it to disk if baseDir is set.
// Disk write is completed before memory cache is updated to maintain consistency.
func (km *KeyManager) Save(dkp *DomainKeyPair) error {
	if dkp == nil {
		return errors.New("cannot save nil domain key pair")
	}
	norm := NormalizeDomain(dkp.Domain)
	if !IsValidDomain(norm) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, dkp.Domain)
	}
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.baseDir != "" {
		filePath := filepath.Join(km.baseDir, norm+".json")
		if err := dkp.SaveToFile(filePath); err != nil {
			return err
		}
	}
	km.keys[norm] = dkp
	return nil
}

// Load retrieves a domain key pair from cache or loads it from disk.
// Returns an error wrapping ErrKeyNotFound if the key does not exist.
func (km *KeyManager) Load(domain string) (*DomainKeyPair, error) {
	norm := NormalizeDomain(domain)
	if !IsValidDomain(norm) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	km.mu.Lock()
	defer km.mu.Unlock()

	if dkp, exists := km.keys[norm]; exists {
		return dkp, nil
	}

	if km.baseDir != "" {
		filePath := filepath.Join(km.baseDir, norm+".json")
		dkp, err := LoadDomainKeyPair(filePath)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("%w: %s (file not found: %s)", ErrKeyNotFound, domain, filePath)
			}
			return nil, err
		}
		km.keys[norm] = dkp
		return dkp, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, domain)
}

// Get returns the cached domain key pair if present in memory.
func (km *KeyManager) Get(domain string) (*DomainKeyPair, bool) {
	norm := NormalizeDomain(domain)
	km.mu.RLock()
	defer km.mu.RUnlock()
	dkp, exists := km.keys[norm]
	return dkp, exists
}

// Add inserts a domain key pair into the memory cache.
func (km *KeyManager) Add(dkp *DomainKeyPair) error {
	if dkp == nil {
		return errors.New("cannot add nil domain key pair")
	}
	norm := NormalizeDomain(dkp.Domain)
	if !IsValidDomain(norm) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, dkp.Domain)
	}
	km.mu.Lock()
	defer km.mu.Unlock()
	km.keys[norm] = dkp
	return nil
}

// Delete removes a domain key pair from cache and disk.
func (km *KeyManager) Delete(domain string) error {
	norm := NormalizeDomain(domain)
	if !IsValidDomain(norm) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	km.mu.Lock()
	defer km.mu.Unlock()
	delete(km.keys, norm)

	if km.baseDir != "" {
		filePath := filepath.Join(km.baseDir, norm+".json")
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete key file %s: %w", filePath, err)
		}
	}
	return nil
}

// Sign signs a message using the domain's loaded private key.
func (km *KeyManager) Sign(domain string, message []byte) ([]byte, error) {
	dkp, err := km.Load(domain)
	if err != nil {
		return nil, err
	}
	return dkp.Sign(message)
}

// ListDomains returns a deterministic, sorted list of all domains available
// in memory and persisted on disk (if baseDir is set).
func (km *KeyManager) ListDomains() []string {
	km.mu.RLock()
	defer km.mu.RUnlock()

	seen := make(map[string]struct{})
	for d := range km.keys {
		seen[d] = struct{}{}
	}

	if km.baseDir != "" {
		if entries, err := os.ReadDir(km.baseDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
					name := strings.TrimSuffix(entry.Name(), ".json")
					norm := NormalizeDomain(name)
					if IsValidDomain(norm) {
						seen[norm] = struct{}{}
					}
				}
			}
		}
	}

	domains := make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}
