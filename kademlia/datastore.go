package kademlia

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"d7024e/registry"
	"errors"
)

var (
	// ErrKeyMismatch is returned when storing a key-value pair where K != hash(V) and K != hash("domain:package:latest").
	ErrKeyMismatch = errors.New("key does not match SHA-256 hash of value")
	// ErrValueTooLarge is returned if a value exceeds the maximum configured size.
	ErrValueTooLarge = errors.New("value exceeds maximum allowed size")
)

const DefaultMaxValSize = 64 * 1024 // Probably changing later for arbitrary size with tcp.

// RecordFetcher retrieves raw bytes for a version record hash from the DHT or external source.
type RecordFetcher func(hash string) ([]byte, error)

// DataStore represents an in-memory thread-safe key-value store for Kademlia values.
type DataStore struct {
	mu            sync.RWMutex
	data          map[KademliaID][]byte
	maxValSize    int
	dnsResolver   registry.DNSResolver
	recordFetcher RecordFetcher
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

// SetDNSResolver configures the DNS resolver used for domain ownership verification.
func (ds *DataStore) SetDNSResolver(resolver registry.DNSResolver) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.dnsResolver = resolver
}

// DNSResolver returns the configured DNS resolver.
func (ds *DataStore) DNSResolver() registry.DNSResolver {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.dnsResolver
}

// SetRecordFetcher sets the callback used to fetch missing records during catch-up.
func (ds *DataStore) SetRecordFetcher(fetcher RecordFetcher) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.recordFetcher = fetcher
}

// RecordFetcher returns the configured record fetcher callback.
func (ds *DataStore) RecordFetcher() RecordFetcher {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.recordFetcher
}

// Validate checks whether a (key, value) pair is permissible to store.
//   - If key == sha256(value): accept (Part 1 blobs and Part 2 VersionRecords).
//   - If key == sha256("domain:package:latest") and value is a valid LatestPointer:
//     run validation checks (signature via DNSResolver, version monotonicity, history chain linkage).
//   - Otherwise: returns ErrKeyMismatch.
func (ds *DataStore) Validate(key KademliaID, value []byte) error {
	ds.mu.RLock()
	maxSize := ds.maxValSize
	ds.mu.RUnlock()
	if maxSize > 0 && len(value) > maxSize {
		return ErrValueTooLarge
	}

	expectedHash := sha256.Sum256(value)
	if KademliaID(expectedHash) == key {
		return nil
	}

	lp, err := registry.ParseLatestPointer(value)
	if err != nil {
		return ErrKeyMismatch
	}

	if KademliaID(lp.DHTKeyBytes()) != key {
		return ErrKeyMismatch
	}

	ds.mu.RLock()
	existingBytes, hasExisting := ds.data[key]
	var existingLP *registry.LatestPointer
	if hasExisting {
		existingLP, _ = registry.ParseLatestPointer(existingBytes)
	}
	ds.mu.RUnlock()

	return ds.validateLatestPointerWithExisting(lp, existingLP, false)
}

func (ds *DataStore) validateLatestPointerWithExisting(lp *registry.LatestPointer, existingLP *registry.LatestPointer, enableSaver bool) error {
	ds.mu.RLock()
	resolver := ds.dnsResolver
	fetcher := ds.recordFetcher
	ds.mu.RUnlock()

	getter := func(hash string) ([]byte, error) {
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != IDLength {
			return nil, fmt.Errorf("invalid hash length: %s", hash)
		}
		var hID KademliaID
		copy(hID[:], decoded)

		ds.mu.RLock()
		localVal, found := ds.data[hID]
		ds.mu.RUnlock()
		if found {
			valCopy := make([]byte, len(localVal))
			copy(valCopy, localVal)
			return valCopy, nil
		}
		if fetcher != nil {
			val, err := fetcher(hash)
			if err == nil && len(val) > 0 {
				return val, nil
			}
			if err != nil {
				return nil, err
			}
		}
		return nil, registry.ErrMissingVersionRecord
	}

	var saver registry.RecordSaver
	if enableSaver {
		saver = func(hash string, data []byte) {
			decoded, err := hex.DecodeString(hash)
			if err != nil || len(decoded) != IDLength {
				return
			}
			var hID KademliaID
			copy(hID[:], decoded)

			valCopy := make([]byte, len(data))
			copy(valCopy, data)
			ds.mu.Lock()
			if _, exists := ds.data[hID]; !exists {
				ds.data[hID] = valCopy
			}
			ds.mu.Unlock()
		}
	}

	return registry.ValidateLatestPointerChain(lp, existingLP, resolver, getter, saver)
}

// Store validates and stores the given key-value pair.
// Rejects the store if validation fails or if size exceeds maxValSize.
// Uses optimistic concurrency control for mutable LatestPointer records to prevent history fork races.
func (ds *DataStore) Store(key KademliaID, value []byte) error {
	ds.mu.RLock()
	maxSize := ds.maxValSize
	ds.mu.RUnlock()
	if maxSize > 0 && len(value) > maxSize {
		return ErrValueTooLarge
	}

	expectedHash := sha256.Sum256(value)
	if KademliaID(expectedHash) == key {
		ds.mu.Lock()
		defer ds.mu.Unlock()
		valCopy := make([]byte, len(value))
		copy(valCopy, value)
		ds.data[key] = valCopy
		return nil
	}

	// Non-content-addressable: must be a valid LatestPointer
	lp, err := registry.ParseLatestPointer(value)
	if err != nil {
		return ErrKeyMismatch
	}

	if KademliaID(lp.DHTKeyBytes()) != key {
		return ErrKeyMismatch
	}

	// Optimistic concurrency retry loop for LatestPointer
	for {
		ds.mu.RLock()
		existingBytes, hasExisting := ds.data[key]
		var existingBytesCopy []byte
		var existingLP *registry.LatestPointer
		if hasExisting {
			existingBytesCopy = make([]byte, len(existingBytes))
			copy(existingBytesCopy, existingBytes)
			existingLP, _ = registry.ParseLatestPointer(existingBytesCopy)
		}
		ds.mu.RUnlock()

		// Validate against current existing latest pointer, saving intermediate records on success
		if err := ds.validateLatestPointerWithExisting(lp, existingLP, true); err != nil {
			return err
		}

		ds.mu.Lock()
		currentBytes, currentExists := ds.data[key]
		unchanged := (!hasExisting && !currentExists) ||
			(hasExisting && currentExists && bytes.Equal(existingBytesCopy, currentBytes))

		if unchanged {
			valCopy := make([]byte, len(value))
			copy(valCopy, value)
			ds.data[key] = valCopy
			ds.mu.Unlock()
			return nil
		}
		// Stored state changed concurrently while validating; re-validate against latest state
		ds.mu.Unlock()
	}
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

// GetAllKeys returns a slice of all stored keys (for replication and CLI 'show ds').
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
