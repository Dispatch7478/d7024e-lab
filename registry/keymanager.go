package registry

import (
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
	ErrInvalidDomain = errors.New("invalid domain name")
	ErrKeyNotFound   = errors.New("domain key not found")
)

var domainNameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

func IsValidDomain(domain string) bool {
	norm := NormalizeDomain(domain)
	if norm == "" || len(norm) > 253 || strings.Contains(norm, "/") || strings.Contains(norm, "\\") || strings.Contains(norm, "..") {
		return false
	}
	return domainNameRegex.MatchString(norm)
}

type domainKeyDTO struct {
	Domain     string    `json:"domain"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"private_key"`
	CreatedAt  time.Time `json:"created_at"`
}

func (dkp *DomainKeyPair) SaveToFile(filePath string) error {
	if dkp == nil {
		return errors.New("cannot save nil domain key pair")
	}
	data, err := json.MarshalIndent(domainKeyDTO{
		Domain:     dkp.Domain,
		PublicKey:  EncodePublicKeyHex(dkp.PublicKey),
		PrivateKey: EncodePrivateKeyHex(dkp.PrivateKey),
		CreatedAt:  dkp.CreatedAt,
	}, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(filePath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	return os.WriteFile(filePath, data, 0644)
}

func LoadDomainKeyPair(filePath string) (*DomainKeyPair, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var dto domainKeyDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, err
	}
	pub, err := DecodePublicKeyHex(dto.PublicKey)
	if err != nil {
		return nil, err
	}
	priv, err := DecodePrivateKeyHex(dto.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &DomainKeyPair{Domain: dto.Domain, PublicKey: pub, PrivateKey: priv, CreatedAt: dto.CreatedAt}, nil
}

type KeyManager struct {
	mu      sync.RWMutex
	baseDir string
	keys    map[string]*DomainKeyPair
}

func NewKeyManager(baseDir string) (*KeyManager, error) {
	if baseDir != "" {
		if err := os.MkdirAll(baseDir, 0755); err != nil {
			return nil, err
		}
	}
	return &KeyManager{baseDir: baseDir, keys: make(map[string]*DomainKeyPair)}, nil
}

func (km *KeyManager) Generate(domain string) (*DomainKeyPair, error) {
	dkp, err := GenerateDomainKeyPair(domain)
	if err != nil {
		return nil, err
	}
	return dkp, km.Save(dkp)
}

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
		if err := dkp.SaveToFile(filepath.Join(km.baseDir, norm+".json")); err != nil {
			return err
		}
	}
	km.keys[norm] = dkp
	return nil
}

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
		dkp, err := LoadDomainKeyPair(filepath.Join(km.baseDir, norm+".json"))
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, domain)
			}
			return nil, err
		}
		km.keys[norm] = dkp
		return dkp, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, domain)
}

func (km *KeyManager) Get(domain string) (*DomainKeyPair, bool) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	dkp, ok := km.keys[NormalizeDomain(domain)]
	return dkp, ok
}

func (km *KeyManager) Add(dkp *DomainKeyPair) error { return km.Save(dkp) }

func (km *KeyManager) Delete(domain string) error {
	norm := NormalizeDomain(domain)
	if !IsValidDomain(norm) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	km.mu.Lock()
	defer km.mu.Unlock()
	delete(km.keys, norm)
	if km.baseDir != "" {
		_ = os.Remove(filepath.Join(km.baseDir, norm+".json"))
	}
	return nil
}

func (km *KeyManager) Sign(domain string, msg []byte) ([]byte, error) {
	dkp, err := km.Load(domain)
	if err != nil {
		return nil, err
	}
	return dkp.Sign(msg)
}

func (km *KeyManager) ListDomains() []string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	seen := make(map[string]bool)
	for d := range km.keys {
		seen[d] = true
	}
	if km.baseDir != "" {
		if entries, err := os.ReadDir(km.baseDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
					name := strings.TrimSuffix(entry.Name(), ".json")
					if norm := NormalizeDomain(name); IsValidDomain(norm) {
						seen[norm] = true
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
