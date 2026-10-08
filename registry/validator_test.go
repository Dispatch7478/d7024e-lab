package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// Helper to create and sign a full release (blob, VersionRecord, LatestPointer)
func createSignedRelease(
	t *testing.T,
	dkp *DomainKeyPair,
	pkg string,
	version string,
	blobContent string,
	prevVRHash string,
) ([]byte, *VersionRecord, []byte, string, *LatestPointer, []byte) {
	t.Helper()

	blobBytes := []byte(blobContent)
	blobHash := ComputeBlobHash(blobBytes)

	vr, err := NewVersionRecord(dkp.Domain, pkg, version, blobHash, prevVRHash)
	if err != nil {
		t.Fatalf("failed to create VersionRecord: %v", err)
	}
	if err := vr.SignWithKeyPair(dkp); err != nil {
		t.Fatalf("failed to sign VersionRecord: %v", err)
	}
	vrBytes, err := vr.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to get canonical VersionRecord bytes: %v", err)
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
		t.Fatalf("failed to get canonical LatestPointer bytes: %v", err)
	}

	return blobBytes, vr, vrBytes, vrHash, lp, lpBytes
}

func TestValidateLatestPointerChain_InitialPublication(t *testing.T) {
	domain := "example.com"
	pkg := "cool-tool"

	dkp, err := GenerateDomainKeyPair(domain)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	_, vr1, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "blob v1", ZeroHash)

	store := map[string][]byte{
		vr1Hash: vr1Bytes,
	}
	getter := func(hash string) ([]byte, error) {
		val, ok := store[hash]
		if !ok {
			return nil, ErrMissingVersionRecord
		}
		return val, nil
	}
	saved := make(map[string][]byte)
	saver := func(hash string, data []byte) {
		saved[hash] = data
	}

	// Initial publication of v1.0.0 (no existing pointer)
	err = ValidateLatestPointerChain(lp1, nil, resolver, getter, saver)
	if err != nil {
		t.Fatalf("expected valid initial publication, got: %v", err)
	}
	if _, ok := saved[vr1Hash]; !ok {
		t.Errorf("expected vr1 to be saved")
	}

	// Initial publication of v2.0.0 when node has no prior pointer (chain: v2.0.0 -> v1.0.0 -> ZeroHash)
	_, vr2, vr2Bytes, vr2Hash, lp2, _ := createSignedRelease(t, dkp, pkg, "2.0.0", "blob v2", vr1Hash)
	store[vr2Hash] = vr2Bytes

	savedMulti := make(map[string][]byte)
	saverMulti := func(hash string, data []byte) {
		savedMulti[hash] = data
	}

	err = ValidateLatestPointerChain(lp2, nil, resolver, getter, saverMulti)
	if err != nil {
		t.Fatalf("expected valid initial publication with full chain, got: %v", err)
	}
	if len(savedMulti) != 2 {
		t.Errorf("expected 2 records saved during catch-up, got %d", len(savedMulti))
	}
	if _, ok := savedMulti[vr2Hash]; !ok {
		t.Errorf("expected vr2 to be saved")
	}
	if _, ok := savedMulti[vr1Hash]; !ok {
		t.Errorf("expected vr1 to be saved")
	}

	_ = vr1
	_ = vr2
}

func TestValidateLatestPointerChain_ForwardUpdates(t *testing.T) {
	domain := "example.com"
	pkg := "my-lib"

	dkp, err := GenerateDomainKeyPair(domain)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	store := make(map[string][]byte)
	getter := func(hash string) ([]byte, error) {
		val, ok := store[hash]
		if !ok {
			return nil, ErrMissingVersionRecord
		}
		return val, nil
	}

	// Step 1: v1.0.0
	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "blob 1", ZeroHash)
	store[vr1Hash] = vr1Bytes
	if err := ValidateLatestPointerChain(lp1, nil, resolver, getter, nil); err != nil {
		t.Fatalf("v1.0.0 failed: %v", err)
	}

	// Step 2: v1.1.0 (forward update from v1.0.0)
	_, _, vr2Bytes, vr2Hash, lp2, _ := createSignedRelease(t, dkp, pkg, "1.1.0", "blob 1.1", vr1Hash)
	store[vr2Hash] = vr2Bytes
	if err := ValidateLatestPointerChain(lp2, lp1, resolver, getter, nil); err != nil {
		t.Fatalf("v1.1.0 update failed: %v", err)
	}

	// Step 3: v2.0.0 (forward update from v1.1.0)
	_, _, vr3Bytes, vr3Hash, lp3, _ := createSignedRelease(t, dkp, pkg, "2.0.0", "blob 2.0", vr2Hash)
	store[vr3Hash] = vr3Bytes
	if err := ValidateLatestPointerChain(lp3, lp2, resolver, getter, nil); err != nil {
		t.Fatalf("v2.0.0 update failed: %v", err)
	}

	// Step 4: Multi-hop forward update (node had v1.0.0, receives v2.0.0; chain connects through v1.1.0)
	savedHop := make(map[string][]byte)
	saverHop := func(hash string, data []byte) {
		savedHop[hash] = data
	}
	if err := ValidateLatestPointerChain(lp3, lp1, resolver, getter, saverHop); err != nil {
		t.Fatalf("multi-hop update failed: %v", err)
	}
	if _, ok := savedHop[vr3Hash]; !ok {
		t.Errorf("expected vr3 saved")
	}
	if _, ok := savedHop[vr2Hash]; !ok {
		t.Errorf("expected intermediate vr2 saved during catch-up")
	}
}

func TestValidateLatestPointerChain_Rule1_OwnerSignature(t *testing.T) {
	domain := "example.com"
	pkg := "secure-pkg"

	dkpOwner, _ := GenerateDomainKeyPair(domain)
	dkpAttacker, _ := GenerateDomainKeyPair(domain) // same domain name, different key!
	dkpOtherDomain, _ := GenerateDomainKeyPair("other.org")

	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkpOwner.PublicKey)

	_, _, vrBytes, vrHash, lpValid, _ := createSignedRelease(t, dkpOwner, pkg, "1.0.0", "blob 1", ZeroHash)
	store := map[string][]byte{vrHash: vrBytes}
	getter := func(hash string) ([]byte, error) { return store[hash], nil }

	// Case 1: Valid signature passes
	if err := ValidateLatestPointerChain(lpValid, nil, resolver, getter, nil); err != nil {
		t.Fatalf("expected valid signature to pass, got: %v", err)
	}

	// Case 2: Nil DNSResolver -> ErrNoDNSResolver
	if err := ValidateLatestPointerChain(lpValid, nil, nil, getter, nil); !errors.Is(err, ErrNoDNSResolver) {
		t.Errorf("expected ErrNoDNSResolver, got: %v", err)
	}

	// Case 3: Domain not in DNSResolver -> ErrUnauthorized
	emptyResolver := NewMockDNSResolver()
	if err := ValidateLatestPointerChain(lpValid, nil, emptyResolver, getter, nil); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized when domain not in DNS, got: %v", err)
	}

	// Case 4: Pointer signed by attacker with different key -> ErrUnauthorized
	lpAttacker, _ := NewLatestPointer(domain, pkg, "1.0.0", vrHash)
	_ = lpAttacker.Sign(dkpAttacker.PrivateKey)
	if err := ValidateLatestPointerChain(lpAttacker, nil, resolver, getter, nil); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for forged signature, got: %v", err)
	}

	// Case 5: Pointer signed with other domain key -> ErrUnauthorized
	lpOther, _ := NewLatestPointer(domain, pkg, "1.0.0", vrHash)
	_ = lpOther.Sign(dkpOtherDomain.PrivateKey)
	if err := ValidateLatestPointerChain(lpOther, nil, resolver, getter, nil); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for other domain key, got: %v", err)
	}

	// Case 6: Pointer with tampered signature string -> ErrUnauthorized
	lpTampered, _ := NewLatestPointer(domain, pkg, "1.0.0", vrHash)
	lpTampered.Signature = lpValid.Signature
	sigBytes, _ := hex.DecodeString(lpTampered.Signature)
	sigBytes[0] ^= 0xFF
	lpTampered.Signature = hex.EncodeToString(sigBytes)
	if err := ValidateLatestPointerChain(lpTampered, nil, resolver, getter, nil); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for tampered signature, got: %v", err)
	}

	// Case 7: Pointer with empty signature -> ErrUnauthorized
	lpNoSig, _ := NewLatestPointer(domain, pkg, "1.0.0", vrHash)
	if err := ValidateLatestPointerChain(lpNoSig, nil, resolver, getter, nil); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for empty signature, got: %v", err)
	}
}

func TestValidateLatestPointerChain_Rule2_RollbackRejection(t *testing.T) {
	domain := "example.com"
	pkg := "my-pkg"

	dkp, _ := GenerateDomainKeyPair(domain)
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "b1", ZeroHash)
	_, _, vr2Bytes, vr2Hash, lp2, _ := createSignedRelease(t, dkp, pkg, "2.0.0", "b2", vr1Hash)

	store := map[string][]byte{
		vr1Hash: vr1Bytes,
		vr2Hash: vr2Bytes,
	}
	getter := func(h string) ([]byte, error) { return store[h], nil }

	// Attempt rollback: existing is 2.0.0, incoming is 1.0.0
	err := ValidateLatestPointerChain(lp1, lp2, resolver, getter, nil)
	if !errors.Is(err, ErrVersionRollback) {
		t.Errorf("expected ErrVersionRollback for 1.0.0 -> 2.0.0 rollback, got: %v", err)
	}

	// Attempt equal version update: existing is 2.0.0, incoming is 2.0.0
	err = ValidateLatestPointerChain(lp2, lp2, resolver, getter, nil)
	if !errors.Is(err, ErrVersionRollback) {
		t.Errorf("expected ErrVersionRollback for 2.0.0 -> 2.0.0 update, got: %v", err)
	}

	// Minor rollback: existing is 1.2.0, incoming is 1.1.9
	_, _, vr12Bytes, vr12Hash, lp12, _ := createSignedRelease(t, dkp, pkg, "1.2.0", "b12", vr1Hash)
	_, _, vr119Bytes, vr119Hash, lp119, _ := createSignedRelease(t, dkp, pkg, "1.1.9", "b119", vr1Hash)
	store[vr12Hash] = vr12Bytes
	store[vr119Hash] = vr119Bytes

	err = ValidateLatestPointerChain(lp119, lp12, resolver, getter, nil)
	if !errors.Is(err, ErrVersionRollback) {
		t.Errorf("expected ErrVersionRollback for 1.1.9 against 1.2.0, got: %v", err)
	}
}

func TestValidateLatestPointerChain_Rule3_ForkRejection(t *testing.T) {
	domain := "example.com"
	pkg := "fork-test"

	dkp, _ := GenerateDomainKeyPair(domain)
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	// Legitimate history: VR1 (1.0.0) -> VR2 (2.0.0)
	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "blob 1", ZeroHash)
	_, _, vr2Bytes, vr2Hash, lp2, _ := createSignedRelease(t, dkp, pkg, "2.0.0", "blob 2", vr1Hash)

	// Forked history: VR_alt (1.0.0-alt) -> VR3_fork (3.0.0) (does NOT link to VR2!)
	_, _, vrAltBytes, vrAltHash, _, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "blob 1 alt", ZeroHash)
	_, _, vr3ForkBytes, vr3ForkHash, lp3Fork, _ := createSignedRelease(t, dkp, pkg, "3.0.0", "blob 3 fork", vrAltHash)

	store := map[string][]byte{
		vr1Hash:     vr1Bytes,
		vr2Hash:     vr2Bytes,
		vrAltHash:   vrAltBytes,
		vr3ForkHash: vr3ForkBytes,
	}
	getter := func(h string) ([]byte, error) { return store[h], nil }

	// Node currently has lp2 (at vr2Hash).
	// Attacker tries to submit lp3Fork (which chains to vrAlt -> ZeroHash, bypassing vr2!)
	err := ValidateLatestPointerChain(lp3Fork, lp2, resolver, getter, nil)
	if !errors.Is(err, ErrHistoryFork) {
		t.Errorf("expected ErrHistoryFork when chain bypasses existing latest record, got: %v", err)
	}

	// Fork branching directly off VR1, bypassing VR2:
	// VR3_branch (3.0.0) points to VR1 instead of VR2
	_, _, vr3BranchBytes, vr3BranchHash, lp3Branch, _ := createSignedRelease(t, dkp, pkg, "3.0.0", "blob 3 branch", vr1Hash)
	store[vr3BranchHash] = vr3BranchBytes

	err = ValidateLatestPointerChain(lp3Branch, lp2, resolver, getter, nil)
	if !errors.Is(err, ErrHistoryFork) {
		t.Errorf("expected ErrHistoryFork when chain branches before existing latest, got: %v", err)
	}

	// New latest pointer pointing to the exact same VR hash as existing pointer
	lpSameHash, _ := NewLatestPointer(domain, pkg, "3.0.0", vr2Hash)
	_ = lpSameHash.SignWithKeyPair(dkp)
	err = ValidateLatestPointerChain(lpSameHash, lp2, resolver, getter, nil)
	if !errors.Is(err, ErrHistoryFork) {
		t.Errorf("expected ErrHistoryFork when new pointer points to existing record hash, got: %v", err)
	}

	_ = lp1
}

func TestValidateLatestPointerChain_Rule4_CatchUp(t *testing.T) {
	domain := "example.com"
	pkg := "catchup-pkg"

	dkp, _ := GenerateDomainKeyPair(domain)
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	// Chain: VR1 (1.0.0) -> VR2 (1.1.0) -> VR3 (1.2.0) -> VR4 (2.0.0)
	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "b1", ZeroHash)
	_, _, vr2Bytes, vr2Hash, _, _ := createSignedRelease(t, dkp, pkg, "1.1.0", "b2", vr1Hash)
	_, _, vr3Bytes, vr3Hash, _, _ := createSignedRelease(t, dkp, pkg, "1.2.0", "b3", vr2Hash)
	_, _, vr4Bytes, vr4Hash, lp4, _ := createSignedRelease(t, dkp, pkg, "2.0.0", "b4", vr3Hash)

	remoteDHT := map[string][]byte{
		vr1Hash: vr1Bytes,
		vr2Hash: vr2Bytes,
		vr3Hash: vr3Bytes,
		vr4Hash: vr4Bytes,
	}

	getter := func(h string) ([]byte, error) {
		val, ok := remoteDHT[h]
		if !ok {
			return nil, fmt.Errorf("hash %s not found on DHT", h)
		}
		return val, nil
	}

	savedRecords := make(map[string][]byte)
	saver := func(h string, data []byte) {
		savedRecords[h] = data
	}

	// Node only knows about LP1 (v1.0.0). It receives LP4 (v2.0.0).
	// It must catch up on VR4, VR3, VR2!
	err := ValidateLatestPointerChain(lp4, lp1, resolver, getter, saver)
	if err != nil {
		t.Fatalf("expected successful catch-up, got: %v", err)
	}

	if len(savedRecords) != 3 {
		t.Errorf("expected 3 intermediate records saved, got %d", len(savedRecords))
	}
	if _, ok := savedRecords[vr4Hash]; !ok {
		t.Errorf("expected vr4 saved")
	}
	if _, ok := savedRecords[vr3Hash]; !ok {
		t.Errorf("expected vr3 saved")
	}
	if _, ok := savedRecords[vr2Hash]; !ok {
		t.Errorf("expected vr2 saved")
	}

	// Failure cases during catch-up:
	// Case A: Missing record on DHT -> ErrMissingVersionRecord
	delete(remoteDHT, vr2Hash)
	err = ValidateLatestPointerChain(lp4, lp1, resolver, getter, nil)
	if !errors.Is(err, ErrMissingVersionRecord) {
		t.Errorf("expected ErrMissingVersionRecord when DHT missing record, got: %v", err)
	}

	// Case B: DHT returns empty bytes -> ErrMissingVersionRecord
	remoteDHT[vr2Hash] = []byte{}
	err = ValidateLatestPointerChain(lp4, lp1, resolver, getter, nil)
	if !errors.Is(err, ErrMissingVersionRecord) {
		t.Errorf("expected ErrMissingVersionRecord for empty bytes, got: %v", err)
	}

	// Case C: Corrupted record hash on DHT -> ErrCorruptRecord
	remoteDHT[vr2Hash] = []byte("corrupted data not matching hash")
	err = ValidateLatestPointerChain(lp4, lp1, resolver, getter, nil)
	if !errors.Is(err, ErrCorruptRecord) {
		t.Errorf("expected ErrCorruptRecord for hash mismatch, got: %v", err)
	}

	// Case D: Invalid JSON on DHT (hash matches though, via manipulated payload)
	badBytes := []byte("not valid json at all")
	badHash := sha256.Sum256(badBytes)
	badHashStr := hex.EncodeToString(badHash[:])
	lpBad, err := NewLatestPointer(domain, pkg, "3.0.0", badHashStr)
	if err != nil {
		t.Fatalf("failed to create lpBad: %v", err)
	}
	_ = lpBad.SignWithKeyPair(dkp)
	remoteDHT[badHashStr] = badBytes
	err = ValidateLatestPointerChain(lpBad, lp1, resolver, getter, nil)
	if !errors.Is(err, ErrCorruptRecord) {
		t.Errorf("expected ErrCorruptRecord for unparseable record, got: %v", err)
	}
}

func TestValidateLatestPointerChain_IntermediateRecordValidation(t *testing.T) {
	domain := "example.com"
	pkg := "tamper-chain"

	dkpOwner, _ := GenerateDomainKeyPair(domain)
	dkpAttacker, _ := GenerateDomainKeyPair(domain)
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkpOwner.PublicKey)

	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkpOwner, pkg, "1.0.0", "b1", ZeroHash)

	// Step 1: Intermediate record signed by attacker key -> ErrUnauthorized
	vr2Attacker, _ := NewVersionRecord(domain, pkg, "1.1.0", sampleBlobHash(), vr1Hash)
	_ = vr2Attacker.SignWithKeyPair(dkpAttacker)
	vr2AttackerBytes, _ := vr2Attacker.MarshalJSON()
	vr2AttackerHash, _ := vr2Attacker.RecordHash()

	vr3, _ := NewVersionRecord(domain, pkg, "2.0.0", sampleBlobHash(), vr2AttackerHash)
	_ = vr3.SignWithKeyPair(dkpOwner)
	vr3Bytes, _ := vr3.MarshalJSON()
	vr3Hash, _ := vr3.RecordHash()

	lp3, _ := NewLatestPointer(domain, pkg, "2.0.0", vr3Hash)
	_ = lp3.SignWithKeyPair(dkpOwner)

	store := map[string][]byte{
		vr1Hash:         vr1Bytes,
		vr2AttackerHash: vr2AttackerBytes,
		vr3Hash:         vr3Bytes,
	}
	getter := func(h string) ([]byte, error) { return store[h], nil }

	err := ValidateLatestPointerChain(lp3, lp1, resolver, getter, nil)
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized when intermediate record has forged signature, got: %v", err)
	}

	// Step 2: Intermediate record has mismatched package name -> ErrDomainMismatch
	vr2WrongPkg, _ := NewVersionRecord(domain, "other-pkg", "1.1.0", sampleBlobHash(), vr1Hash)
	_ = vr2WrongPkg.SignWithKeyPair(dkpOwner)
	vr2WrongPkgBytes, _ := vr2WrongPkg.MarshalJSON()
	vr2WrongPkgHash, _ := vr2WrongPkg.RecordHash()

	vr3WP, _ := NewVersionRecord(domain, pkg, "2.0.0", sampleBlobHash(), vr2WrongPkgHash)
	_ = vr3WP.SignWithKeyPair(dkpOwner)
	vr3WPBytes, _ := vr3WP.MarshalJSON()
	vr3WPHash, _ := vr3WP.RecordHash()

	lp3WP, _ := NewLatestPointer(domain, pkg, "2.0.0", vr3WPHash)
	_ = lp3WP.SignWithKeyPair(dkpOwner)

	store[vr2WrongPkgHash] = vr2WrongPkgBytes
	store[vr3WPHash] = vr3WPBytes

	err = ValidateLatestPointerChain(lp3WP, lp1, resolver, getter, nil)
	if !errors.Is(err, ErrDomainMismatch) {
		t.Errorf("expected ErrDomainMismatch when intermediate record has wrong pkg, got: %v", err)
	}

	// Step 3: Intermediate record has mismatched domain -> ErrDomainMismatch
	dkpOther, _ := GenerateDomainKeyPair("other.org")
	vr2WrongDomain, _ := NewVersionRecord("other.org", pkg, "1.1.0", sampleBlobHash(), vr1Hash)
	_ = vr2WrongDomain.SignWithKeyPair(dkpOther)
	vr2WrongDomainBytes, _ := vr2WrongDomain.MarshalJSON()
	vr2WrongDomainHash, _ := vr2WrongDomain.RecordHash()

	vr3WD, _ := NewVersionRecord(domain, pkg, "2.0.0", sampleBlobHash(), vr2WrongDomainHash)
	_ = vr3WD.SignWithKeyPair(dkpOwner)
	vr3WDBytes, _ := vr3WD.MarshalJSON()
	vr3WDHash, _ := vr3WD.RecordHash()

	lp3WD, _ := NewLatestPointer(domain, pkg, "2.0.0", vr3WDHash)
	_ = lp3WD.SignWithKeyPair(dkpOwner)

	store[vr2WrongDomainHash] = vr2WrongDomainBytes
	store[vr3WDHash] = vr3WDBytes

	err = ValidateLatestPointerChain(lp3WD, lp1, resolver, getter, nil)
	if !errors.Is(err, ErrDomainMismatch) {
		t.Errorf("expected ErrDomainMismatch when intermediate record has wrong domain, got: %v", err)
	}
}

func TestValidateLatestPointerChain_StructuralIntegrityEdgeCases(t *testing.T) {
	domain := "example.com"
	pkg := "structure-pkg"

	dkp, _ := GenerateDomainKeyPair(domain)
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "b1", ZeroHash)
	store := map[string][]byte{vr1Hash: vr1Bytes}
	getter := func(h string) ([]byte, error) { return store[h], nil }

	// 1. Nil latest pointer -> ErrInvalidLatestPointer
	if err := ValidateLatestPointerChain(nil, nil, resolver, getter, nil); !errors.Is(err, ErrInvalidLatestPointer) {
		t.Errorf("expected ErrInvalidLatestPointer for nil pointer, got: %v", err)
	}

	// 2. Pointer pointing to ZeroHash -> ErrInvalidLatestPointer
	lpZero, _ := NewLatestPointer(domain, pkg, "1.0.0", ZeroHash)
	_ = lpZero.SignWithKeyPair(dkp)
	if err := ValidateLatestPointerChain(lpZero, nil, resolver, getter, nil); !errors.Is(err, ErrInvalidLatestPointer) {
		t.Errorf("expected ErrInvalidLatestPointer for pointer referencing ZeroHash, got: %v", err)
	}

	// 3. Pointer version does not match head version record version -> ErrInvalidHistoryChain
	lpVerMismatch, _ := NewLatestPointer(domain, pkg, "2.0.0", vr1Hash) // points to VR1 which is 1.0.0!
	_ = lpVerMismatch.SignWithKeyPair(dkp)
	if err := ValidateLatestPointerChain(lpVerMismatch, nil, resolver, getter, nil); !errors.Is(err, ErrInvalidHistoryChain) {
		t.Errorf("expected ErrInvalidHistoryChain when pointer version != head record version, got: %v", err)
	}

	// 4. Non-monotonic versions in chain (predecessor version >= successor version)
	// VR2 (version 1.0.0) points to VR1 (version 2.0.0)!
	vrBadOrder1, _ := NewVersionRecord(domain, pkg, "2.0.0", sampleBlobHash(), ZeroHash)
	_ = vrBadOrder1.SignWithKeyPair(dkp)
	vrBadOrder1Bytes, _ := vrBadOrder1.MarshalJSON()
	vrBadOrder1Hash, _ := vrBadOrder1.RecordHash()

	vrBadOrder2, _ := NewVersionRecord(domain, pkg, "1.5.0", sampleBlobHash(), vrBadOrder1Hash) // 1.5.0 points back to 2.0.0!
	_ = vrBadOrder2.SignWithKeyPair(dkp)
	vrBadOrder2Bytes, _ := vrBadOrder2.MarshalJSON()
	vrBadOrder2Hash, _ := vrBadOrder2.RecordHash()

	lpBadOrder, _ := NewLatestPointer(domain, pkg, "1.5.0", vrBadOrder2Hash)
	_ = lpBadOrder.SignWithKeyPair(dkp)

	store[vrBadOrder1Hash] = vrBadOrder1Bytes
	store[vrBadOrder2Hash] = vrBadOrder2Bytes

	if err := ValidateLatestPointerChain(lpBadOrder, nil, resolver, getter, nil); !errors.Is(err, ErrInvalidHistoryChain) {
		t.Errorf("expected ErrInvalidHistoryChain for non-monotonic history chain, got: %v", err)
	}

	// 5. Max depth exceeded triggers ErrInvalidHistoryChain
	_, _, vr2Bytes, vr2Hash, lp2, _ := createSignedRelease(t, dkp, pkg, "2.0.0", "b2", vr1Hash)
	store[vr2Hash] = vr2Bytes
	err := ValidateLatestPointerChainWithDepth(lp2, nil, resolver, getter, nil, 1)
	if !errors.Is(err, ErrInvalidHistoryChain) {
		t.Errorf("expected ErrInvalidHistoryChain when maxDepth exceeded, got: %v", err)
	}

	// 6. Max depth default (0 defaults to 1000) passes for single record
	err = ValidateLatestPointerChainWithDepth(lp1, nil, resolver, getter, nil, 0)
	if err != nil {
		t.Errorf("expected default depth to pass for single record, got: %v", err)
	}

	// 7. Nil getter -> ErrMissingVersionRecord
	if err := ValidateLatestPointerChain(lp1, nil, resolver, nil, nil); !errors.Is(err, ErrMissingVersionRecord) {
		t.Errorf("expected ErrMissingVersionRecord for nil getter, got: %v", err)
	}

	// 8. Existing pointer with domain mismatch
	lpOtherDomain, _ := NewLatestPointer("other.org", pkg, "0.5.0", vr1Hash)
	_ = lpOtherDomain.SignWithKeyPair(dkp) // signature won't match domain but Validate doesn't check sig of existing
	if err := ValidateLatestPointerChain(lp1, lpOtherDomain, resolver, getter, nil); !errors.Is(err, ErrDomainMismatch) {
		t.Errorf("expected ErrDomainMismatch for cross-domain existing pointer, got: %v", err)
	}

	// 9. Existing pointer invalid
	lpCorruptExisting := &LatestPointer{Tag: "not-a-pointer"}
	if err := ValidateLatestPointerChain(lp1, lpCorruptExisting, resolver, getter, nil); err == nil {
		t.Errorf("expected error for corrupted existing pointer")
	}
}

func TestPackageValidator_StructAndMethods(t *testing.T) {
	domain := "example.com"
	pkg := "struct-test"

	dkp, _ := GenerateDomainKeyPair(domain)
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "b1", ZeroHash)
	store := map[string][]byte{vr1Hash: vr1Bytes}
	getter := func(h string) ([]byte, error) { return store[h], nil }

	saved := make(map[string][]byte)
	saver := func(h string, data []byte) { saved[h] = data }

	pv := NewPackageValidator(resolver, getter, saver)
	if pv.Resolver != resolver || pv.MaxChainDepth != DefaultMaxChainDepth {
		t.Errorf("PackageValidator fields not properly initialized")
	}

	err := pv.ValidatePublication(lp1, nil)
	if err != nil {
		t.Fatalf("expected ValidatePublication to pass: %v", err)
	}
	if len(saved) != 1 {
		t.Errorf("expected 1 record saved, got %d", len(saved))
	}

	var nilPV *PackageValidator
	if err := nilPV.ValidatePublication(lp1, nil); err == nil {
		t.Errorf("expected error on nil PackageValidator")
	}
}

func TestValidateLatestPointerChain_PredecessorNotGreaterThanExisting(t *testing.T) {
	domain := "example.com"
	pkg := "mono-test"

	dkp, _ := GenerateDomainKeyPair(domain)
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	// Legitimate release v1.0.0
	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "blob 1", ZeroHash)

	// Malicious chain: VR_dip has version "0.9.0" (< 1.0.0), pointing to VR1 ("1.0.0")!
	// Then VR_top has version "2.0.0", pointing to VR_dip ("0.9.0").
	// lpTop has version "2.0.0".
	_, _, vrDipBytes, vrDipHash, _, _ := createSignedRelease(t, dkp, pkg, "0.9.0", "blob dip", vr1Hash)
	_, _, vrTopBytes, vrTopHash, lpTop, _ := createSignedRelease(t, dkp, pkg, "2.0.0", "blob top", vrDipHash)

	store := map[string][]byte{
		vr1Hash:   vr1Bytes,
		vrDipHash: vrDipBytes,
		vrTopHash: vrTopBytes,
	}
	getter := func(h string) ([]byte, error) { return store[h], nil }

	saved := make(map[string][]byte)
	saver := func(h string, data []byte) { saved[h] = data }

	// Must be rejected because VR_dip (0.9.0) <= existing (1.0.0)!
	err := ValidateLatestPointerChain(lpTop, lp1, resolver, getter, saver)
	if !errors.Is(err, ErrInvalidHistoryChain) {
		t.Errorf("expected ErrInvalidHistoryChain for non-monotonic chain dip before existing, got: %v", err)
	}

	// Because validation failed, saver must NOT have been called
	if len(saved) != 0 {
		t.Errorf("expected 0 saved records on failure, got %d", len(saved))
	}
}

func TestValidateLatestPointerChain_AtomicCommitNoPartialSaveOnFailure(t *testing.T) {
	domain := "example.com"
	pkg := "atomic-test"

	dkpOwner, _ := GenerateDomainKeyPair(domain)
	dkpAttacker, _ := GenerateDomainKeyPair(domain)
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkpOwner.PublicKey)

	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkpOwner, pkg, "1.0.0", "b1", ZeroHash)

	// VR2 is signed by attacker (invalid signature)
	vr2Attacker, _ := NewVersionRecord(domain, pkg, "1.1.0", sampleBlobHash(), vr1Hash)
	_ = vr2Attacker.SignWithKeyPair(dkpAttacker)
	vr2AttackerBytes, _ := vr2Attacker.MarshalJSON()
	vr2AttackerHash, _ := vr2Attacker.RecordHash()

	// VR3 is signed by owner, pointing to VR2
	_, _, vr3Bytes, vr3Hash, lp3, _ := createSignedRelease(t, dkpOwner, pkg, "2.0.0", "b3", vr2AttackerHash)

	store := map[string][]byte{
		vr1Hash:         vr1Bytes,
		vr2AttackerHash: vr2AttackerBytes,
		vr3Hash:         vr3Bytes,
	}
	getter := func(h string) ([]byte, error) { return store[h], nil }

	saved := make(map[string][]byte)
	saver := func(h string, data []byte) { saved[h] = data }

	err := ValidateLatestPointerChain(lp3, lp1, resolver, getter, saver)
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for forged intermediate record, got: %v", err)
	}

	// VR3 was inspected first, but because chain failed at VR2, VR3 must NOT be saved!
	if len(saved) != 0 {
		t.Errorf("expected 0 records saved on chain validation failure, but %d were saved: %v", len(saved), saved)
	}
}

func TestValidateLatestPointerChain_ExistingPointerWithZeroHash(t *testing.T) {
	domain := "example.com"
	pkg := "zero-hash-test"

	dkp, _ := GenerateDomainKeyPair(domain)
	resolver := NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	_, _, vr1Bytes, vr1Hash, lp1, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "b1", ZeroHash)
	store := map[string][]byte{vr1Hash: vr1Bytes}
	getter := func(h string) ([]byte, error) { return store[h], nil }

	// Create an existing pointer that erroneously references ZeroHash
	lpZeroHash := &LatestPointer{
		Tag:               TagLatestPointer,
		Domain:            domain,
		Package:           pkg,
		Version:           "0.5.0",
		VersionRecordHash: ZeroHash,
	}
	_ = lpZeroHash.SignWithKeyPair(dkp)

	err := ValidateLatestPointerChain(lp1, lpZeroHash, resolver, getter, nil)
	if !errors.Is(err, ErrInvalidLatestPointer) {
		t.Errorf("expected ErrInvalidLatestPointer for existing pointer referencing ZeroHash, got: %v", err)
	}
}

func TestWalkVersionChain(t *testing.T) {
	domain := "example.com"
	pkg := "walk-test"
	dkp, _ := GenerateDomainKeyPair(domain)

	// Create 3 releases: 1.0.0 -> 2.0.0 -> 3.0.0
	_, _, vr1Bytes, vr1Hash, _, _ := createSignedRelease(t, dkp, pkg, "1.0.0", "b1", ZeroHash)
	_, _, vr2Bytes, vr2Hash, _, _ := createSignedRelease(t, dkp, pkg, "2.0.0", "b2", vr1Hash)
	_, _, vr3Bytes, vr3Hash, _, _ := createSignedRelease(t, dkp, pkg, "3.0.0", "b3", vr2Hash)

	store := map[string][]byte{
		vr1Hash: vr1Bytes,
		vr2Hash: vr2Bytes,
		vr3Hash: vr3Bytes,
	}
	getter := func(h string) ([]byte, error) {
		val, ok := store[h]
		if !ok {
			return nil, errors.New("not found")
		}
		return val, nil
	}

	// 1. Successful traversal
	chain, err := WalkVersionChain(vr3Hash, getter)
	if err != nil {
		t.Fatalf("unexpected error walking chain: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("expected 3 records, got %d", len(chain))
	}
	if chain[0].Version != "3.0.0" || chain[1].Version != "2.0.0" || chain[2].Version != "1.0.0" {
		t.Errorf("unexpected chain order: %s, %s, %s", chain[0].Version, chain[1].Version, chain[2].Version)
	}

	// 2. Empty or ZeroHash head
	emptyChain, err := WalkVersionChain("", getter)
	if err != nil || len(emptyChain) != 0 {
		t.Errorf("expected empty chain for empty head")
	}
	zeroChain, err := WalkVersionChain(ZeroHash, getter)
	if err != nil || len(zeroChain) != 0 {
		t.Errorf("expected empty chain for ZeroHash head")
	}

	// 3. Nil getter error
	if _, err := WalkVersionChain(vr3Hash, nil); err == nil {
		t.Errorf("expected error for nil getter")
	}

	// 4. Missing record error
	delete(store, vr2Hash)
	if _, err := WalkVersionChain(vr3Hash, getter); !errors.Is(err, ErrMissingVersionRecord) {
		t.Errorf("expected ErrMissingVersionRecord, got: %v", err)
	}
	store[vr2Hash] = vr2Bytes

	// 5. Corrupted content hash
	store[vr2Hash] = []byte("corrupt content")
	if _, err := WalkVersionChain(vr3Hash, getter); !errors.Is(err, ErrCorruptRecord) {
		t.Errorf("expected ErrCorruptRecord, got: %v", err)
	}
	store[vr2Hash] = vr2Bytes

	// 6. Max depth exceeded
	if _, err := WalkVersionChainWithDepth(vr3Hash, getter, 2); !errors.Is(err, ErrInvalidHistoryChain) {
		t.Errorf("expected ErrInvalidHistoryChain when max depth exceeded, got: %v", err)
	}
}
