package kademlia

import (
	"crypto/sha256"
	"errors"
	"sync"
)

var (
	// ErrKeyMismatch is returned when storing a key-value pair where K != hash(V).
	ErrKeyMismatch = errors.New("key does not match SHA-256 hash of value")
	// ErrValueTooLarge is returned if a value exceeds the maximum configured size.
	ErrValueTooLarge = errors.New("value exceeds maximum allowed size")
)

const DefaultMaxValSize = 64 * 1024 // Probably changing later for arbitrary size with tcp.

// DataStore represents an in-memory thread-safe key-value store for Kademlia values.
type DataStore struct {
	mu         sync.RWMutex
	data       map[KademliaID][]byte
	maxValSize int
}

// NewDataStore returns a new initialized DataStore.
func NewDataStore() *DataStore {
	return &DataStore{
		data:       make(map[KademliaID][]byte),
		maxValSize: DefaultMaxValSize,
	}
}

// SetMaxValSize overrides the default maximum allowed value size.
func (ds *DataStore) SetMaxValSize(size int) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.maxValSize = size
}

// Validate checks whether a (key, value) pair is permissible to store.
// Enforces the K = SHA-256(V) content-addressing rule per LAB-SPEC.md.
func (ds *DataStore) Validate(key KademliaID, value []byte) error {
	expectedHash := sha256.Sum256(value)
	if KademliaID(expectedHash) != key {
		return ErrKeyMismatch
	}
	return nil
}

// Store validates and stores the given key-value pair.
// Rejects the store if key != hash(value) or if size exceeds maxValSize.
func (ds *DataStore) Store(key KademliaID, value []byte) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.maxValSize > 0 && len(value) > ds.maxValSize {
		return ErrValueTooLarge
	}

	if err := ds.Validate(key, value); err != nil {
		return err
	}

	// Defensive copy to prevent external mutation races
	valCopy := make([]byte, len(value))
	copy(valCopy, value)
	ds.data[key] = valCopy
	return nil
}

// StoreUnchecked stores a key-value pair without validation.
// Only for testing e.g. simulating a corrupted node.
func (ds *DataStore) StoreUnchecked(key KademliaID, value []byte) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	valCopy := make([]byte, len(value))
	copy(valCopy, value)
	ds.data[key] = valCopy
}

// Get retrieves a copy of the value associated with key.
func (ds *DataStore) Get(key KademliaID) ([]byte, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	val, exists := ds.data[key]
	if !exists {
		return nil, false
	}
	valCopy := make([]byte, len(val))
	copy(valCopy, val)
	return valCopy, true
}

// Has checks if a key is stored.
func (ds *DataStore) Has(key KademliaID) bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	_, exists := ds.data[key]
	return exists
}

// Delete removes a key-value pair from the store.
func (ds *DataStore) Delete(key KademliaID) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if _, exists := ds.data[key]; exists {
		delete(ds.data, key)
		return true
	}
	return false
}

// GetAllKeys returns a slice of all stored keys (for replication and CLI 'show ds')-
func (ds *DataStore) GetAllKeys() []KademliaID {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	keys := make([]KademliaID, 0, len(ds.data))
	for k := range ds.data {
		keys = append(keys, k)
	}
	return keys
}

// Len returns the number of stored items.
func (ds *DataStore) Len() int {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return len(ds.data)
}
