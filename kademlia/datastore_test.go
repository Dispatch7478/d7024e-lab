package kademlia

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestDataStore_StoreAndGet(t *testing.T) {
	ds := NewDataStore()

	val := []byte("hello kademlia distributed systems")
	key := KademliaID(sha256.Sum256(val))

	if err := ds.Store(key, val); err != nil {
		t.Fatalf("expected successful store, got: %v", err)
	}

	if !ds.Has(key) {
		t.Errorf("expected ds.Has(key) to be true")
	}

	retrieved, found := ds.Get(key)
	if !found {
		t.Fatalf("expected key to be found")
	}

	if string(retrieved) != string(val) {
		t.Errorf("expected %s, got %s", string(val), string(retrieved))
	}
}

func TestDataStore_KeyMismatch(t *testing.T) {
	ds := NewDataStore()

	val := []byte("legitimate data")
	fakeKey := KademliaID(sha256.Sum256([]byte("different data")))

	err := ds.Store(fakeKey, val)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("expected ErrKeyMismatch, got %v", err)
	}

	if ds.Has(fakeKey) {
		t.Errorf("expected fake key to NOT be stored")
	}
}

func TestDataStore_ValueTooLarge(t *testing.T) {
	ds := NewDataStore()
	ds.SetMaxValSize(10) // 10 bytes limit

	val := []byte("this data is definitely longer than 10 bytes")
	key := KademliaID(sha256.Sum256(val))

	err := ds.Store(key, val)
	if !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("expected ErrValueTooLarge, got %v", err)
	}
}

func TestDataStore_GetNotFound(t *testing.T) {
	ds := NewDataStore()
	key := KademliaID(sha256.Sum256([]byte("non-existent")))

	val, found := ds.Get(key)
	if found || val != nil {
		t.Errorf("expected not found for missing key")
	}
}

func TestDataStore_DefensiveCopy(t *testing.T) {
	ds := NewDataStore()

	val := []byte("mutable slice")
	key := KademliaID(sha256.Sum256(val))

	if err := ds.Store(key, val); err != nil {
		t.Fatalf("store failed: %v", err)
	}

	// Mutate original slice after store
	val[0] = 'X'

	retrieved, _ := ds.Get(key)
	if retrieved[0] == 'X' {
		t.Errorf("store did not make defensive copy of input slice")
	}

	// Mutate returned slice
	retrieved[0] = 'Y'

	retrievedAgain, _ := ds.Get(key)
	if retrievedAgain[0] == 'Y' {
		t.Errorf("get did not return defensive copy of stored slice")
	}
}

func TestDataStore_DeleteAndLen(t *testing.T) {
	ds := NewDataStore()

	val1 := []byte("value one")
	key1 := KademliaID(sha256.Sum256(val1))

	val2 := []byte("value two")
	key2 := KademliaID(sha256.Sum256(val2))

	_ = ds.Store(key1, val1)
	_ = ds.Store(key2, val2)

	if ds.Len() != 2 {
		t.Errorf("expected len 2, got %d", ds.Len())
	}

	keys := ds.GetAllKeys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}

	if !ds.Delete(key1) {
		t.Errorf("expected Delete to return true for existing key")
	}

	if ds.Delete(key1) {
		t.Errorf("expected Delete to return false for already deleted key")
	}

	if ds.Len() != 1 {
		t.Errorf("expected len 1 after deletion, got %d", ds.Len())
	}
}

func TestDataStore_Validate(t *testing.T) {
	ds := NewDataStore()

	val := []byte("correct content")
	key := KademliaID(sha256.Sum256(val))

	if err := ds.Validate(key, val); err != nil {
		t.Errorf("expected Validate to pass for matching key-value, got %v", err)
	}

	mismatchedKey := KademliaID(sha256.Sum256([]byte("wrong content")))
	if err := ds.Validate(mismatchedKey, val); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("expected ErrKeyMismatch, got %v", err)
	}
}

func TestDataStore_StoreUnchecked(t *testing.T) {
	ds := NewDataStore()

	val := []byte("corrupted data")
	arbitraryKey := KademliaID(sha256.Sum256([]byte("different hash")))

	// StoreUnchecked must bypass validation
	ds.StoreUnchecked(arbitraryKey, val)

	retrieved, found := ds.Get(arbitraryKey)
	if !found {
		t.Fatalf("expected key to be found after StoreUnchecked")
	}
	if string(retrieved) != string(val) {
		t.Errorf("expected %s, got %s", string(val), string(retrieved))
	}
}

func TestDataStore_ConcurrentAccess(t *testing.T) {
	ds := NewDataStore()
	const numGoroutines = 20
	const opsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				data := []byte(fmt.Sprintf("goroutine-%d-item-%d", id, i))
				key := KademliaID(sha256.Sum256(data))

				_ = ds.Store(key, data)
				_, _ = ds.Get(key)
				_ = ds.Has(key)
				_ = ds.Len()
				_ = ds.GetAllKeys()
			}
		}(g)
	}

	wg.Wait()

	if ds.Len() != numGoroutines*opsPerGoroutine {
		t.Errorf("expected %d items, got %d", numGoroutines*opsPerGoroutine, ds.Len())
	}
}
