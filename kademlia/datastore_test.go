package kademlia

import (
	"crypto/sha256"
	"d7024e/registry"
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

func createTestRelease(
	t *testing.T,
	dkp *registry.DomainKeyPair,
	pkg string,
	version string,
	blobContent string,
	prevVRHash string,
) ([]byte, *registry.VersionRecord, []byte, string, *registry.LatestPointer, []byte, KademliaID) {
	t.Helper()

	blobBytes := []byte(blobContent)
	blobHash := registry.ComputeBlobHash(blobBytes)

	vr, err := registry.NewVersionRecord(dkp.Domain, pkg, version, blobHash, prevVRHash)
	if err != nil {
		t.Fatalf("failed to create VersionRecord: %v", err)
	}
	if err := vr.SignWithKeyPair(dkp); err != nil {
		t.Fatalf("failed to sign VersionRecord: %v", err)
	}
	vrBytes, err := vr.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal VersionRecord: %v", err)
	}
	vrHash, err := vr.RecordHash()
	if err != nil {
		t.Fatalf("failed to get VersionRecord hash: %v", err)
	}

	lp, err := vr.NewLatestPointer()
	if err != nil {
		t.Fatalf("failed to create LatestPointer: %v", err)
	}
	if err := lp.SignWithKeyPair(dkp); err != nil {
		t.Fatalf("failed to sign LatestPointer: %v", err)
	}
	lpBytes, err := lp.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal LatestPointer: %v", err)
	}
	lpKey := KademliaID(lp.DHTKeyBytes())

	return blobBytes, vr, vrBytes, vrHash, lp, lpBytes, lpKey
}

func TestDataStore_ValidateContentAddressedBlobs(t *testing.T) {
	ds := NewDataStore()

	// Part arbitrary blob
	blob := []byte("arbitrary binary payload")
	blobKey := KademliaID(sha256.Sum256(blob))
	if err := ds.Validate(blobKey, blob); err != nil {
		t.Errorf("expected Validate to pass for Part 1 blob, got: %v", err)
	}

	// Part VersionRecord
	dkp, _ := registry.GenerateDomainKeyPair("example.com")
	_, _, vrBytes, vrHash, _, _, _ := createTestRelease(t, dkp, "pkg-one", "1.0.0", "b1", registry.ZeroHash)
	vrKey := *NewKademliaID(vrHash)

	if err := ds.Validate(vrKey, vrBytes); err != nil {
		t.Errorf("expected Validate to pass for VersionRecord, got: %v", err)
	}

	if err := ds.Store(vrKey, vrBytes); err != nil {
		t.Errorf("expected Store to succeed for VersionRecord, got: %v", err)
	}
}

func TestDataStore_LatestPointerInitialPublication(t *testing.T) {
	domain := "example.com"
	pkg := "my-app"

	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	ds := NewDataStore()
	ds.SetDNSResolver(resolver)

	_, _, vr1Bytes, vr1Hash, _, lp1Bytes, lp1Key := createTestRelease(t, dkp, pkg, "1.0.0", "b1", registry.ZeroHash)

	// Store the version record first in ds
	vr1Key := *NewKademliaID(vr1Hash)
	if err := ds.Store(vr1Key, vr1Bytes); err != nil {
		t.Fatalf("failed to store vr1: %v", err)
	}

	// Validate and Store LatestPointer
	if err := ds.Validate(lp1Key, lp1Bytes); err != nil {
		t.Fatalf("expected Validate to pass for initial LatestPointer: %v", err)
	}

	if err := ds.Store(lp1Key, lp1Bytes); err != nil {
		t.Fatalf("expected Store to succeed for initial LatestPointer: %v", err)
	}

	if !ds.Has(lp1Key) {
		t.Errorf("expected ds to have lp1Key")
	}

	retrieved, found := ds.Get(lp1Key)
	if !found {
		t.Fatalf("expected lp1 to be found")
	}
	if string(retrieved) != string(lp1Bytes) {
		t.Errorf("stored bytes mismatch")
	}
}

func TestDataStore_LatestPointerForwardUpdate(t *testing.T) {
	domain := "example.com"
	pkg := "my-app"

	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	ds := NewDataStore()
	ds.SetDNSResolver(resolver)

	_, _, vr1Bytes, vr1Hash, _, lp1Bytes, lp1Key := createTestRelease(t, dkp, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, _, lp2Bytes, _ := createTestRelease(t, dkp, pkg, "2.0.0", "b2", vr1Hash)

	_ = ds.Store(*NewKademliaID(vr1Hash), vr1Bytes)
	_ = ds.Store(lp1Key, lp1Bytes)

	_ = ds.Store(*NewKademliaID(vr2Hash), vr2Bytes)

	// Forward update to v2.0.0
	if err := ds.Store(lp1Key, lp2Bytes); err != nil {
		t.Fatalf("expected forward update to succeed, got: %v", err)
	}

	retrieved, _ := ds.Get(lp1Key)
	lpParsed, err := registry.ParseLatestPointer(retrieved)
	if err != nil {
		t.Fatalf("failed to parse updated pointer: %v", err)
	}
	if lpParsed.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", lpParsed.Version)
	}
}

func TestDataStore_RejectionRules(t *testing.T) {
	domain := "example.com"
	pkg := "reject-test"

	dkpOwner, _ := registry.GenerateDomainKeyPair(domain)
	dkpAttacker, _ := registry.GenerateDomainKeyPair(domain)

	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkpOwner.PublicKey)

	_, _, vr1Bytes, vr1Hash, _, lp1Bytes, lpKey := createTestRelease(t, dkpOwner, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, _, lp2Bytes, _ := createTestRelease(t, dkpOwner, pkg, "2.0.0", "b2", vr1Hash)

	// No DNS resolver configured -> ErrNoDNSResolver
	dsNoDNS := NewDataStore()
	_ = dsNoDNS.Store(*NewKademliaID(vr1Hash), vr1Bytes)
	err := dsNoDNS.Store(lpKey, lp1Bytes)
	if !errors.Is(err, ErrNoDNSResolver) {
		t.Errorf("expected ErrNoDNSResolver without DNS resolver, got: %v", err)
	}

	// Setup valid DataStore
	ds := NewDataStore()
	ds.SetDNSResolver(resolver)
	_ = ds.Store(*NewKademliaID(vr1Hash), vr1Bytes)
	_ = ds.Store(*NewKademliaID(vr2Hash), vr2Bytes)
	_ = ds.Store(lpKey, lp2Bytes) // current latest is 2.0.0

	// Rollback rejection: attempt to store 1.0.0 over 2.0.0 -> ErrVersionRollback
	err = ds.Store(lpKey, lp1Bytes)
	if !errors.Is(err, ErrVersionRollback) {
		t.Errorf("expected ErrVersionRollback for 1.0.0 over 2.0.0, got: %v", err)
	}

	// Equal version rejection: attempt to re-store 2.0.0 -> ErrVersionRollback
	err = ds.Store(lpKey, lp2Bytes)
	if !errors.Is(err, ErrVersionRollback) {
		t.Errorf("expected ErrVersionRollback for equal version 2.0.0 over 2.0.0, got: %v", err)
	}

	// Unauthorized signature rejection -> ErrUnauthorized
	_, _, vr3AttackerBytes, vr3AttackerHash, _, lp3AttackerBytes, _ := createTestRelease(t, dkpAttacker, pkg, "3.0.0", "b3", vr2Hash)
	_ = ds.Store(*NewKademliaID(vr3AttackerHash), vr3AttackerBytes)
	err = ds.Store(lpKey, lp3AttackerBytes)
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for forged pointer, got: %v", err)
	}

	// Fork rejection: v3.0.0 points to alternative root v1.0.0-alt instead of v2.0.0
	_, _, vrAltBytes, vrAltHash, _, _, _ := createTestRelease(t, dkpOwner, pkg, "1.0.0", "alt root", registry.ZeroHash)
	_, _, vr3ForkBytes, vr3ForkHash, _, lp3ForkBytes, _ := createTestRelease(t, dkpOwner, pkg, "3.0.0", "fork", vrAltHash)
	_ = ds.Store(*NewKademliaID(vrAltHash), vrAltBytes)
	_ = ds.Store(*NewKademliaID(vr3ForkHash), vr3ForkBytes)

	err = ds.Store(lpKey, lp3ForkBytes)
	if !errors.Is(err, ErrHistoryFork) {
		t.Errorf("expected ErrHistoryFork for branching history, got: %v", err)
	}

	// Storing LatestPointer under a random key -> ErrKeyMismatch
	randomKey := *NewRandomKademliaID()
	err = ds.Store(randomKey, lp1Bytes)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("expected ErrKeyMismatch for wrong key, got: %v", err)
	}

	// Storing arbitrary bytes under latest key -> ErrKeyMismatch
	err = ds.Store(lpKey, []byte("arbitrary blob not a latest pointer"))
	if !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("expected ErrKeyMismatch for non-pointer value at latest key, got: %v", err)
	}
}

func TestDataStore_CatchUp(t *testing.T) {
	domain := "example.com"
	pkg := "catchup-ds"

	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	ds := NewDataStore()
	ds.SetDNSResolver(resolver)

	_, _, vr1Bytes, vr1Hash, _, _, _ := createTestRelease(t, dkp, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, _, _, _ := createTestRelease(t, dkp, pkg, "1.1.0", "b2", vr1Hash)
	_, _, vr3Bytes, vr3Hash, _, lp3Bytes, lpKey := createTestRelease(t, dkp, pkg, "2.0.0", "b3", vr2Hash)

	// Remote storage representing DHT
	dhtStore := map[string][]byte{
		vr1Hash: vr1Bytes,
		vr2Hash: vr2Bytes,
		vr3Hash: vr3Bytes,
	}

	// Wire record fetcher to simulate network DHT lookup
	ds.SetRecordFetcher(func(hash string) ([]byte, error) {
		val, ok := dhtStore[hash]
		if !ok {
			return nil, fmt.Errorf("hash %s not found on remote DHT", hash)
		}
		return val, nil
	})

	// ds does NOT have VR1, VR2, VR3 locally!
	if ds.Has(*NewKademliaID(vr1Hash)) || ds.Has(*NewKademliaID(vr2Hash)) || ds.Has(*NewKademliaID(vr3Hash)) {
		t.Fatalf("ds should be empty before catch-up")
	}

	// Store v2.0.0: ds must catch up by fetching all three VRs
	if err := ds.Store(lpKey, lp3Bytes); err != nil {
		t.Fatalf("expected successful store with catch-up, got: %v", err)
	}

	// Verify all 3 records were retrieved and cached locally into DataStore!
	if !ds.Has(*NewKademliaID(vr1Hash)) {
		t.Errorf("expected vr1 to be cached in DataStore after catch-up")
	}
	if !ds.Has(*NewKademliaID(vr2Hash)) {
		t.Errorf("expected vr2 to be cached in DataStore after catch-up")
	}
	if !ds.Has(*NewKademliaID(vr3Hash)) {
		t.Errorf("expected vr3 to be cached in DataStore after catch-up")
	}
	if !ds.Has(lpKey) {
		t.Errorf("expected lpKey to be stored in DataStore")
	}

	// Test fetcher failure
	delete(dhtStore, vr2Hash)
	dsFailing := NewDataStore()
	dsFailing.SetDNSResolver(resolver)
	dsFailing.SetRecordFetcher(func(hash string) ([]byte, error) {
		val, ok := dhtStore[hash]
		if !ok {
			return nil, fmt.Errorf("not found")
		}
		return val, nil
	})

	err := dsFailing.Store(lpKey, lp3Bytes)
	if !errors.Is(err, ErrMissingVersionRecord) {
		t.Errorf("expected ErrMissingVersionRecord when catch-up fetcher fails, got: %v", err)
	}
}

func TestDataStore_SettersAndGetters(t *testing.T) {
	ds := NewDataStore()
	if ds.DNSResolver() != nil {
		t.Errorf("expected initial nil DNSResolver")
	}
	if ds.RecordFetcher() != nil {
		t.Errorf("expected initial nil RecordFetcher")
	}

	mockRes := registry.NewMockDNSResolver()
	ds.SetDNSResolver(mockRes)
	if ds.DNSResolver() != mockRes {
		t.Errorf("DNSResolver setter/getter mismatch")
	}

	fetcher := func(h string) ([]byte, error) { return nil, nil }
	ds.SetRecordFetcher(fetcher)
	if ds.RecordFetcher() == nil {
		t.Errorf("RecordFetcher setter/getter mismatch")
	}
}

func TestDataStore_ValidateIsReadOnly(t *testing.T) {
	domain := "example.com"
	pkg := "readonly-test"

	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	ds := NewDataStore()
	ds.SetDNSResolver(resolver)

	_, _, vr1Bytes, vr1Hash, _, _, _ := createTestRelease(t, dkp, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, _, lp2Bytes, lpKey := createTestRelease(t, dkp, pkg, "2.0.0", "b2", vr1Hash)

	dhtStore := map[string][]byte{
		vr1Hash: vr1Bytes,
		vr2Hash: vr2Bytes,
	}
	ds.SetRecordFetcher(func(hash string) ([]byte, error) {
		val, ok := dhtStore[hash]
		if !ok {
			return nil, fmt.Errorf("not found")
		}
		return val, nil
	})

	// Calling ds.Validate must succeed
	if err := ds.Validate(lpKey, lp2Bytes); err != nil {
		t.Fatalf("expected Validate to succeed: %v", err)
	}

	// But ds must still be empty! Validate is strictly read-only.
	if ds.Len() != 0 {
		t.Errorf("expected ds to be completely empty after Validate, but has %d items", ds.Len())
	}
	if ds.Has(*NewKademliaID(vr1Hash)) || ds.Has(*NewKademliaID(vr2Hash)) || ds.Has(lpKey) {
		t.Errorf("expected no records cached in DataStore from Validate call")
	}
}

func TestDataStore_NoPartialCacheOnFailure(t *testing.T) {
	domain := "example.com"
	pkg := "nopartial-test"

	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	ds := NewDataStore()
	ds.SetDNSResolver(resolver)

	_, _, vr1Bytes, vr1Hash, _, _, _ := createTestRelease(t, dkp, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, _, vr2Hash, _, _, _ := createTestRelease(t, dkp, pkg, "1.1.0", "b2", vr1Hash)
	_, _, vr3Bytes, vr3Hash, _, lp3Bytes, lpKey := createTestRelease(t, dkp, pkg, "2.0.0", "b3", vr2Hash)

	// Remote store only has VR3. VR2 is missing!
	dhtStore := map[string][]byte{
		vr1Hash: vr1Bytes,
		// vr2Hash missing!
		vr3Hash: vr3Bytes,
	}
	ds.SetRecordFetcher(func(hash string) ([]byte, error) {
		val, ok := dhtStore[hash]
		if !ok {
			return nil, fmt.Errorf("hash missing")
		}
		return val, nil
	})

	err := ds.Store(lpKey, lp3Bytes)
	if !errors.Is(err, ErrMissingVersionRecord) {
		t.Fatalf("expected ErrMissingVersionRecord, got: %v", err)
	}

	// Since VR2 failed, VR3 must NOT have been left cached in ds!
	if ds.Has(*NewKademliaID(vr3Hash)) {
		t.Errorf("expected VR3 not to be cached in DataStore after failed store")
	}
	if ds.Len() != 0 {
		t.Errorf("expected ds to remain empty on failure, but has %d items", ds.Len())
	}
}

func TestDataStore_ConcurrentStoresForkPrevention(t *testing.T) {
	domain := "example.com"
	pkg := "concurrent-fork"

	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	ds := NewDataStore()
	ds.SetDNSResolver(resolver)

	// Base release v1.0.0
	_, _, vr1Bytes, vr1Hash, _, lp1Bytes, lpKey := createTestRelease(t, dkp, pkg, "1.0.0", "b1", registry.ZeroHash)
	_ = ds.Store(*NewKademliaID(vr1Hash), vr1Bytes)
	_ = ds.Store(lpKey, lp1Bytes)

	// Legitimate path: v2.0.0 -> v1.0.0
	_, _, vr2Bytes, vr2Hash, _, lp2Bytes, _ := createTestRelease(t, dkp, pkg, "2.0.0", "b2", vr1Hash)
	_ = ds.Store(*NewKademliaID(vr2Hash), vr2Bytes)

	// Forked path: v3.0.0-fork -> v1.0.0-alt (does not link to v2.0.0!)
	_, _, vrAltBytes, vrAltHash, _, _, _ := createTestRelease(t, dkp, pkg, "1.0.0", "alt root", registry.ZeroHash)
	_, _, vrForkBytes, vrForkHash, _, lpForkBytes, _ := createTestRelease(t, dkp, pkg, "3.0.0", "forked v3", vrAltHash)
	_ = ds.Store(*NewKademliaID(vrAltHash), vrAltBytes)
	_ = ds.Store(*NewKademliaID(vrForkHash), vrForkBytes)

	// Concurrent race: Goroutine 1 writes v2.0.0, Goroutine 2 attempts v3.0.0-fork
	// Even if Goroutine 2 begins validating before v2.0.0 is committed,
	// optimistic concurrency control in Store must detect the concurrent mutation,
	// re-validate against v2.0.0, and REJECT v3.0.0-fork with ErrHistoryFork!
	var wg sync.WaitGroup
	var errFork error
	var errLegit error

	wg.Add(2)
	go func() {
		defer wg.Done()
		errLegit = ds.Store(lpKey, lp2Bytes)
	}()
	go func() {
		defer wg.Done()
		errFork = ds.Store(lpKey, lpForkBytes)
	}()
	wg.Wait()

	if errLegit != nil {
		t.Errorf("legitimate store failed: %v", errLegit)
	}
	if !errors.Is(errFork, ErrHistoryFork) {
		t.Errorf("expected ErrHistoryFork for concurrent fork attempt, got: %v", errFork)
	}

	// Ensure the stored latest pointer is v2.0.0
	val, found := ds.Get(lpKey)
	if !found {
		t.Fatalf("expected latest pointer to be stored")
	}
	lp, err := registry.ParseLatestPointer(val)
	if err != nil {
		t.Fatalf("failed to parse stored pointer: %v", err)
	}
	if lp.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", lp.Version)
	}
}

func TestDataStore_SafeHashDecodingNoPanic(t *testing.T) {
	domain := "example.com"
	pkg := "safe-hash"

	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	ds := NewDataStore()
	ds.SetDNSResolver(resolver)

	// Wire a fetcher that returns invalid non-hex / short strings
	ds.SetRecordFetcher(func(hash string) ([]byte, error) {
		return []byte("dummy"), nil
	})

	_, _, vr1Bytes, vr1Hash, _, _, _ := createTestRelease(t, dkp, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, _, lp2Bytes, lpKey := createTestRelease(t, dkp, pkg, "2.0.0", "b2", vr1Hash)
	_ = ds.Store(*NewKademliaID(vr1Hash), vr1Bytes)
	_ = ds.Store(*NewKademliaID(vr2Hash), vr2Bytes)

	// Valid validation of normal release passes without panic
	if err := ds.Validate(lpKey, lp2Bytes); err != nil {
		t.Errorf("expected Validate to pass: %v", err)
	}
}
