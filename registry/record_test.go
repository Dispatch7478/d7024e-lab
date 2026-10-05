package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func sampleBlob() []byte {
	return []byte("sample package binary blob content v1.0.0")
}

func sampleBlobHash() string {
	return ComputeBlobHash(sampleBlob())
}

func TestIsValidPackageName(t *testing.T) {
	valid := []string{
		"a",
		"pkg",
		"my-package",
		"my_package",
		"my.package",
		"java-pair",
		"package123",
		"A-Package.Name_1",
		strings.Repeat("a", 128),
	}
	for _, name := range valid {
		if !IsValidPackageName(name) {
			t.Errorf("expected %q to be valid package name", name)
		}
	}

	invalid := []string{
		"",
		"   ",
		"-pkg",
		"_pkg",
		".pkg",
		"pkg-",
		"pkg.",
		"pkg/",
		"pkg\\",
		"pkg..name",
		"../pkg",
		"pkg/sub",
		"pkg name",
		"pkg@1",
		strings.Repeat("a", 129),
	}
	for _, name := range invalid {
		if IsValidPackageName(name) {
			t.Errorf("expected %q to be invalid package name", name)
		}
	}
}

func TestComputeBlobHash(t *testing.T) {
	data := []byte("hello world")
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	got := ComputeBlobHash(data)
	if got != expected {
		t.Fatalf("expected blob hash %s, got %s", expected, got)
	}
}

func TestVersionRecord_CreationAndValidation(t *testing.T) {
	blobHash := sampleBlobHash()

	// Initial version with empty prev
	vr1, err := NewVersionRecord("example.com", "my-pkg", "1.0.0", blobHash, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !vr1.IsInitialVersion() {
		t.Fatal("expected vr1 to be initial version")
	}
	if vr1.PreviousVersionRecord != ZeroHash {
		t.Fatalf("expected PreviousVersionRecord to default to ZeroHash, got %s", vr1.PreviousVersionRecord)
	}
	if vr1.Tag != TagVersionRecord {
		t.Fatalf("expected tag %s, got %s", TagVersionRecord, vr1.Tag)
	}

	// Initial version helper
	vrInitial, err := NewInitialVersionRecord("example.com", "my-pkg", "1.0.0", blobHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !vrInitial.IsInitialVersion() || vrInitial.PreviousVersionRecord != ZeroHash {
		t.Fatal("expected NewInitialVersionRecord to create an initial record")
	}

	// Subsequent version with previous record hash
	dummyPrevHash := strings.Repeat("a", 64)
	vr2, err := NewVersionRecord("example.com", "my-pkg", "1.1.0", blobHash, dummyPrevHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vr2.IsInitialVersion() {
		t.Fatal("expected vr2 to NOT be initial version")
	}
	if vr2.PreviousVersionRecord != dummyPrevHash {
		t.Fatalf("expected prev record %s, got %s", dummyPrevHash, vr2.PreviousVersionRecord)
	}

	// Validation errors
	badCases := []struct {
		domain    string
		pkg       string
		version   string
		blobHash  string
		prev      string
		expectErr error
	}{
		{"", "pkg", "1.0.0", blobHash, "", ErrInvalidDomain},
		{"invalid..domain", "pkg", "1.0.0", blobHash, "", ErrInvalidDomain},
		{"example.com", "", "1.0.0", blobHash, "", ErrInvalidPackageName},
		{"example.com", "-invalid-pkg", "1.0.0", blobHash, "", ErrInvalidPackageName},
		{"example.com", "pkg", "not-a-ver", blobHash, "", ErrInvalidVersion},
		{"example.com", "pkg", "1.0.0", "short", "", ErrInvalidBlobHash},
		{"example.com", "pkg", "1.0.0", strings.Repeat("z", 64), "", ErrInvalidBlobHash},
		{"example.com", "pkg", "1.0.0", blobHash, "bad-prev", ErrInvalidRecordHash},
	}

	for _, tc := range badCases {
		_, err := NewVersionRecord(tc.domain, tc.pkg, tc.version, tc.blobHash, tc.prev)
		if err == nil {
			t.Errorf("expected error for case domain=%q pkg=%q version=%q, got nil", tc.domain, tc.pkg, tc.version)
		} else if !errors.Is(err, tc.expectErr) {
			t.Errorf("expected error %v, got %v", tc.expectErr, err)
		}
	}

	// Validate on nil and corrupted tag
	var nilVR *VersionRecord
	if err := nilVR.Validate(); err == nil {
		t.Fatal("expected error on nil record validate")
	}
	if nilVR.IsInitialVersion() {
		t.Fatal("expected false for nilVR.IsInitialVersion()")
	}

	vr1.Tag = "wrong-tag"
	if err := vr1.Validate(); !errors.Is(err, ErrInvalidRecordTag) {
		t.Fatalf("expected ErrInvalidRecordTag, got %v", err)
	}

	// Struct validation branches
	vrValid, _ := NewVersionRecord("example.com", "pkg", "1.0.0", blobHash, "")
	badVR := *vrValid
	badVR.Domain = "invalid..domain"
	if err := badVR.Validate(); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("expected ErrInvalidDomain, got %v", err)
	}
	badVR = *vrValid
	badVR.Package = ""
	if err := badVR.Validate(); !errors.Is(err, ErrInvalidPackageName) {
		t.Fatalf("expected ErrInvalidPackageName, got %v", err)
	}
	badVR = *vrValid
	badVR.Version = "bad"
	if err := badVR.Validate(); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("expected ErrInvalidVersion, got %v", err)
	}
	badVR = *vrValid
	badVR.BlobHash = "bad"
	if err := badVR.Validate(); !errors.Is(err, ErrInvalidBlobHash) {
		t.Fatalf("expected ErrInvalidBlobHash, got %v", err)
	}
	badVR = *vrValid
	badVR.PreviousVersionRecord = "bad"
	if err := badVR.Validate(); !errors.Is(err, ErrInvalidRecordHash) {
		t.Fatalf("expected ErrInvalidRecordHash, got %v", err)
	}
}

func TestVersionRecord_ParsedVersionAndCompare(t *testing.T) {
	blobHash := sampleBlobHash()
	vr1, _ := NewVersionRecord("example.com", "pkg", "1.0.0", blobHash, "")
	vr2, _ := NewVersionRecord("example.com", "pkg", "2.0.0", blobHash, "")

	v1, err := vr1.ParsedVersion()
	if err != nil || v1.Major != 1 {
		t.Fatalf("failed to parse version: %v", err)
	}

	cmp, err := vr1.CompareVersion(vr2)
	if err != nil || cmp != -1 {
		t.Fatalf("expected -1, got %d, err=%v", cmp, err)
	}

	cmp, err = vr2.CompareVersion(vr1)
	if err != nil || cmp != 1 {
		t.Fatalf("expected 1, got %d, err=%v", cmp, err)
	}

	var nilVR *VersionRecord
	if _, err := nilVR.ParsedVersion(); err == nil {
		t.Fatal("expected error on nil ParsedVersion")
	}
	if _, err := nilVR.CompareVersion(vr1); err == nil {
		t.Fatal("expected error on nil receiver CompareVersion")
	}
	if _, err := vr1.CompareVersion(nilVR); err == nil {
		t.Fatal("expected error on nil CompareVersion")
	}

	// Bad version string in record
	badVR := *vr1
	badVR.Version = "invalid"
	if _, err := badVR.CompareVersion(vr2); err == nil {
		t.Fatal("expected error on bad version compare")
	}
	if _, err := vr2.CompareVersion(&badVR); err == nil {
		t.Fatal("expected error on bad version compare target")
	}
}

func TestVersionRecord_SigningAndVerification(t *testing.T) {
	dkp, err := GenerateDomainKeyPair("example.com")
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	blobHash := sampleBlobHash()
	vr, err := NewVersionRecord("example.com", "my-pkg", "1.0.0", blobHash, "")
	if err != nil {
		t.Fatalf("failed to create version record: %v", err)
	}

	// Payload hash determinism
	h1, err := vr.PayloadHash()
	if err != nil {
		t.Fatalf("failed to compute payload hash: %v", err)
	}
	hHex, err := vr.PayloadHashHex()
	if err != nil || hHex != hex.EncodeToString(h1[:]) {
		t.Fatalf("payload hash hex mismatch")
	}

	// Unsigned verify should fail
	if err := vr.Verify(dkp.PublicKey); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}

	// Sign with mismatched domain key pair should fail
	wrongDKP, _ := GenerateDomainKeyPair("other.org")
	if err := vr.SignWithKeyPair(wrongDKP); !errors.Is(err, ErrDomainMismatch) {
		t.Fatalf("expected ErrDomainMismatch, got %v", err)
	}

	// Sign with nil key pair
	if err := vr.SignWithKeyPair(nil); err == nil {
		t.Fatal("expected error signing with nil key pair")
	}

	// Sign with nil record
	var nilVR *VersionRecord
	if err := nilVR.Sign(dkp.PrivateKey); err == nil {
		t.Fatal("expected error signing with nil record")
	}
	if err := nilVR.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected error verifying with nil record")
	}
	if err := nilVR.VerifyWithResolver(NewMockDNSResolver()); err == nil {
		t.Fatal("expected error verifying with nil record on resolver")
	}
	if err := vr.VerifyWithResolver(nil); err == nil {
		t.Fatal("expected error verifying with nil resolver")
	}

	// Sign with invalid private key length
	if err := vr.Sign(ed25519.PrivateKey([]byte("short"))); err == nil {
		t.Fatal("expected error signing with short key")
	}

	// Valid signing
	if err := vr.SignWithKeyPair(dkp); err != nil {
		t.Fatalf("failed to sign with key pair: %v", err)
	}
	if vr.Signature == "" {
		t.Fatal("signature is empty after signing")
	}

	// Valid verification
	if err := vr.Verify(dkp.PublicKey); err != nil {
		t.Fatalf("verification failed with valid key: %v", err)
	}

	// Verification with DNS Resolver
	dns := NewMockDNSResolver()
	if err := dns.SetKey("example.com", dkp.PublicKey); err != nil {
		t.Fatalf("failed to set dns key: %v", err)
	}
	if err := vr.VerifyWithResolver(dns); err != nil {
		t.Fatalf("verification with DNS resolver failed: %v", err)
	}

	// Verification with DNS Resolver missing domain
	dnsEmpty := NewMockDNSResolver()
	if err := vr.VerifyWithResolver(dnsEmpty); err == nil {
		t.Fatal("expected verification failure when domain not in DNS resolver")
	}

	// Verify with wrong public key
	otherPub, _, _ := GenerateKeyPair()
	if err := vr.Verify(otherPub); err == nil {
		t.Fatal("expected verification failure with wrong public key")
	}
}

func TestVersionRecord_TamperDetection(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("example.com")
	blobHash := sampleBlobHash()

	makeSignedRecord := func() *VersionRecord {
		vr, _ := NewVersionRecord("example.com", "my-pkg", "1.0.0", blobHash, "")
		_ = vr.SignWithKeyPair(dkp)
		return vr
	}

	// Tamper Tag
	vr := makeSignedRecord()
	vr.Tag = "tampered-tag"
	if err := vr.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on tampered Tag")
	}

	// Tamper Domain
	vr = makeSignedRecord()
	vr.Domain = "attacker.com"
	if err := vr.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on tampered Domain")
	}

	// Tamper Package
	vr = makeSignedRecord()
	vr.Package = "different-pkg"
	if err := vr.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on tampered Package")
	}

	// Tamper Version
	vr = makeSignedRecord()
	vr.Version = "2.0.0"
	if err := vr.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on tampered Version")
	}

	// Tamper BlobHash
	vr = makeSignedRecord()
	vr.BlobHash = ComputeBlobHash([]byte("malicious binary"))
	if err := vr.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on tampered BlobHash")
	}

	// Tamper PreviousVersionRecord
	vr = makeSignedRecord()
	vr.PreviousVersionRecord = strings.Repeat("f", 64)
	if err := vr.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on tampered PreviousVersionRecord")
	}

	// Corrupt Signature
	vr = makeSignedRecord()
	vr.Signature = hex.EncodeToString([]byte("corrupted-sig-that-is-not-64-bytes"))
	if err := vr.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on corrupted signature")
	}
}

func TestVersionRecord_ContentAddressableRecordHash(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("example.com")
	vr, _ := NewVersionRecord("example.com", "my-pkg", "1.0.0", sampleBlobHash(), "")

	// RecordHash on unsigned record should error
	if _, err := vr.RecordHash(); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature on unsigned RecordHash, got %v", err)
	}
	if _, err := vr.RecordHashBytes(); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature on unsigned RecordHashBytes, got %v", err)
	}

	// Nil receiver checks
	var nilVR *VersionRecord
	if _, err := nilVR.RecordHash(); err == nil {
		t.Fatal("expected error on nilVR.RecordHash")
	}
	if _, err := nilVR.RecordHashBytes(); err == nil {
		t.Fatal("expected error on nilVR.RecordHashBytes")
	}

	// Sign record
	_ = vr.SignWithKeyPair(dkp)

	// RecordHash must match SHA-256 of vr.MarshalJSON()
	jsonData, err := vr.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	expectedHash := sha256.Sum256(jsonData)
	expectedHex := hex.EncodeToString(expectedHash[:])

	recHash, err := vr.RecordHash()
	if err != nil || recHash != expectedHex {
		t.Fatalf("RecordHash mismatch: expected %s, got %s, err=%v", expectedHex, recHash, err)
	}

	recHashBytes, err := vr.RecordHashBytes()
	if err != nil || recHashBytes != expectedHash {
		t.Fatalf("RecordHashBytes mismatch: expected %x, got %x", expectedHash, recHashBytes)
	}
}

func TestVersionRecord_JSONSerialization_And_LenientKeys(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("example.com")
	vr, _ := NewVersionRecord("example.com", "my-pkg", "1.0.0", sampleBlobHash(), "")
	_ = vr.SignWithKeyPair(dkp)

	// Standard roundtrip
	data, err := json.Marshal(vr)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var vr2 VersionRecord
	if err := json.Unmarshal(data, &vr2); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if vr2 != *vr {
		t.Fatalf("unmarshaled record %+v != original %+v", vr2, *vr)
	}
	if err := vr2.Verify(dkp.PublicKey); err != nil {
		t.Fatalf("verification of unmarshaled record failed: %v", err)
	}

	// Nil marshal
	var nilVR *VersionRecord
	if _, err := nilVR.MarshalJSON(); err == nil {
		t.Fatal("expected error on nilVR.MarshalJSON")
	}

	// Invalid record marshal
	badVR := *vr
	badVR.Tag = "bad"
	if _, err := badVR.MarshalJSON(); err == nil {
		t.Fatal("expected error on invalid record MarshalJSON")
	}

	// Lenient deserialization with snake_case and short keys
	altJSON := `{
		"tag": "version-record",
		"domain_name": "example.com",
		"package_name": "my-pkg",
		"version": "1.0.0",
		"blob_hash": "` + sampleBlobHash() + `",
		"previous_version_record": "` + ZeroHash + `",
		"signature": "` + vr.Signature + `"
	}`

	var vrAlt VersionRecord
	if err := json.Unmarshal([]byte(altJSON), &vrAlt); err != nil {
		t.Fatalf("failed to unmarshal alt JSON: %v", err)
	}
	if err := vrAlt.Verify(dkp.PublicKey); err != nil {
		t.Fatalf("verification of lenient unmarshaled record failed: %v", err)
	}

	// Short key variants: "domain", "package", "prev_version_record", "sig"
	altJSON2 := `{
		"tag": "version-record",
		"domain": "example.com",
		"package": "my-pkg",
		"version": "1.0.0",
		"blobHash": "` + sampleBlobHash() + `",
		"prev_version_record": "` + ZeroHash + `",
		"sig": "` + vr.Signature + `"
	}`
	var vrAlt2 VersionRecord
	if err := json.Unmarshal([]byte(altJSON2), &vrAlt2); err != nil {
		t.Fatalf("failed to unmarshal alt JSON 2: %v", err)
	}
	if vrAlt2.Domain != "example.com" || vrAlt2.Package != "my-pkg" {
		t.Fatal("failed to unmarshal short keys")
	}
}

func TestVersionRecord_NewLatestPointer(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("example.com")
	vr, _ := NewVersionRecord("example.com", "my-pkg", "1.0.0", sampleBlobHash(), "")
	_ = vr.SignWithKeyPair(dkp)

	lp, err := vr.NewLatestPointer()
	if err != nil {
		t.Fatalf("failed to create LatestPointer from VersionRecord: %v", err)
	}

	recHash, _ := vr.RecordHash()
	if lp.VersionRecordHash != recHash {
		t.Fatalf("expected VersionRecordHash %s, got %s", recHash, lp.VersionRecordHash)
	}
	if lp.Domain != vr.Domain || lp.Package != vr.Package || lp.Version != vr.Version {
		t.Fatal("LatestPointer fields do not match VersionRecord")
	}

	// MatchesRecord
	matches, err := lp.MatchesRecord(vr)
	if err != nil || !matches {
		t.Fatalf("MatchesRecord should be true: %v", err)
	}

	// MatchesRecord with different version record
	vrDiff, _ := NewVersionRecord("example.com", "my-pkg", "2.0.0", sampleBlobHash(), "")
	_ = vrDiff.SignWithKeyPair(dkp)
	matches, err = lp.MatchesRecord(vrDiff)
	if err != nil || matches {
		t.Fatal("MatchesRecord should be false for different version")
	}

	// MatchesRecord with domain / pkg / unsigned record
	vrDiffDomain, _ := NewVersionRecord("other.com", "my-pkg", "1.0.0", sampleBlobHash(), "")
	matches, _ = lp.MatchesRecord(vrDiffDomain)
	if matches {
		t.Fatal("MatchesRecord should be false for different domain")
	}
	vrDiffPkg, _ := NewVersionRecord("example.com", "other-pkg", "1.0.0", sampleBlobHash(), "")
	matches, _ = lp.MatchesRecord(vrDiffPkg)
	if matches {
		t.Fatal("MatchesRecord should be false for different package")
	}

	// Nil checks
	var nilVR *VersionRecord
	if _, err := nilVR.NewLatestPointer(); err == nil {
		t.Fatal("expected error on nilVR.NewLatestPointer")
	}
	if _, err := lp.MatchesRecord(nilVR); err == nil {
		t.Fatal("expected error on lp.MatchesRecord(nil)")
	}
	var nilLP *LatestPointer
	if _, err := nilLP.MatchesRecord(vr); err == nil {
		t.Fatal("expected error on nilLP.MatchesRecord")
	}
}

func TestLatestPointer_CreationValidationAndDHTKey(t *testing.T) {
	vrHash := strings.Repeat("b", 64)
	lp, err := NewLatestPointer("rfin.ch", "java-pair", "1.2.3", vrHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lp.Tag != TagLatestPointer {
		t.Fatalf("expected tag %s, got %s", TagLatestPointer, lp.Tag)
	}

	// DHT Key validation
	expectedKeyStr := "rfin.ch:java-pair:latest"
	if lp.DHTKeyString() != expectedKeyStr {
		t.Fatalf("expected key string %s, got %s", expectedKeyStr, lp.DHTKeyString())
	}
	expectedHash := sha256.Sum256([]byte(expectedKeyStr))
	expectedHex := hex.EncodeToString(expectedHash[:])

	if lp.DHTKey() != expectedHex {
		t.Fatalf("expected DHTKey %s, got %s", expectedHex, lp.DHTKey())
	}
	if lp.DHTKeyBytes() != expectedHash {
		t.Fatalf("expected DHTKeyBytes %x, got %x", expectedHash, lp.DHTKeyBytes())
	}

	// Free function DHT Key helpers
	if LatestPointerKeyString("rfin.ch", "java-pair") != expectedKeyStr {
		t.Fatal("LatestPointerKeyString mismatch")
	}
	if LatestPointerDHTKey("rfin.ch", "java-pair") != expectedHex {
		t.Fatal("LatestPointerDHTKey mismatch")
	}
	if LatestPointerDHTKeyBytes("rfin.ch", "java-pair") != expectedHash {
		t.Fatal("LatestPointerDHTKeyBytes mismatch")
	}

	// Nil LP DHT methods
	var nilLP *LatestPointer
	if nilLP.DHTKeyString() != "" {
		t.Fatal("expected empty string on nilLP.DHTKeyString")
	}
	if nilLP.DHTKey() != "" {
		t.Fatal("expected empty string on nilLP.DHTKey")
	}
	if nilLP.DHTKeyBytes() != [32]byte{} {
		t.Fatal("expected zero bytes on nilLP.DHTKeyBytes")
	}

	// Validation errors
	badCases := []struct {
		domain    string
		pkg       string
		version   string
		vrHash    string
		expectErr error
	}{
		{"", "pkg", "1.0.0", vrHash, ErrInvalidDomain},
		{"rfin.ch", "", "1.0.0", vrHash, ErrInvalidPackageName},
		{"rfin.ch", "pkg", "invalid", vrHash, ErrInvalidVersion},
		{"rfin.ch", "pkg", "1.0.0", "short", ErrInvalidRecordHash},
	}
	for _, tc := range badCases {
		_, err := NewLatestPointer(tc.domain, tc.pkg, tc.version, tc.vrHash)
		if err == nil || !errors.Is(err, tc.expectErr) {
			t.Errorf("expected %v, got %v", tc.expectErr, err)
		}
	}

	// Nil and corrupted tag
	if err := nilLP.Validate(); err == nil {
		t.Fatal("expected error on nil LatestPointer validate")
	}
	lp.Tag = "bad-tag"
	if err := lp.Validate(); !errors.Is(err, ErrInvalidRecordTag) {
		t.Fatalf("expected ErrInvalidRecordTag, got %v", err)
	}

	// Field validation branches
	lpValid, _ := NewLatestPointer("rfin.ch", "java-pair", "1.0.0", vrHash)
	badLP := *lpValid
	badLP.Domain = "invalid..domain"
	if err := badLP.Validate(); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("expected ErrInvalidDomain, got %v", err)
	}
	badLP = *lpValid
	badLP.Package = ""
	if err := badLP.Validate(); !errors.Is(err, ErrInvalidPackageName) {
		t.Fatalf("expected ErrInvalidPackageName, got %v", err)
	}
	badLP = *lpValid
	badLP.Version = "bad"
	if err := badLP.Validate(); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("expected ErrInvalidVersion, got %v", err)
	}
	badLP = *lpValid
	badLP.VersionRecordHash = "bad"
	if err := badLP.Validate(); !errors.Is(err, ErrInvalidRecordHash) {
		t.Fatalf("expected ErrInvalidRecordHash, got %v", err)
	}
}

func TestLatestPointer_ParsedVersionAndCompare(t *testing.T) {
	vrHash := strings.Repeat("b", 64)
	lp1, _ := NewLatestPointer("rfin.ch", "java-pair", "1.0.0", vrHash)
	lp2, _ := NewLatestPointer("rfin.ch", "java-pair", "1.1.0", vrHash)

	v1, err := lp1.ParsedVersion()
	if err != nil || v1.String() != "1.0.0" {
		t.Fatalf("failed to parse version: %v", err)
	}

	cmp, err := lp1.CompareVersion(lp2)
	if err != nil || cmp != -1 {
		t.Fatalf("expected -1, got %d, err=%v", cmp, err)
	}

	var nilLP *LatestPointer
	if _, err := nilLP.ParsedVersion(); err == nil {
		t.Fatal("expected error on nil ParsedVersion")
	}
	if _, err := nilLP.CompareVersion(lp1); err == nil {
		t.Fatal("expected error on nil receiver CompareVersion")
	}
	if _, err := lp1.CompareVersion(nilLP); err == nil {
		t.Fatal("expected error on nil CompareVersion")
	}

	badLP := *lp1
	badLP.Version = "bad"
	if _, err := badLP.CompareVersion(lp2); err == nil {
		t.Fatal("expected error on bad version compare")
	}
	if _, err := lp2.CompareVersion(&badLP); err == nil {
		t.Fatal("expected error on bad version compare target")
	}
}

func TestLatestPointer_SigningVerificationAndTamper(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("rfin.ch")
	vrHash := strings.Repeat("c", 64)

	lp, err := NewLatestPointer("rfin.ch", "java-pair", "1.0.0", vrHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Payload hash determinism
	h1, err := lp.PayloadHash()
	if err != nil {
		t.Fatalf("failed to compute payload hash: %v", err)
	}
	hHex, err := lp.PayloadHashHex()
	if err != nil || hHex != hex.EncodeToString(h1[:]) {
		t.Fatalf("payload hash hex mismatch")
	}

	// Unsigned verify
	if err := lp.Verify(dkp.PublicKey); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}

	// Domain mismatch
	wrongDKP, _ := GenerateDomainKeyPair("other.com")
	if err := lp.SignWithKeyPair(wrongDKP); !errors.Is(err, ErrDomainMismatch) {
		t.Fatalf("expected ErrDomainMismatch, got %v", err)
	}
	if err := lp.SignWithKeyPair(nil); err == nil {
		t.Fatal("expected error on nil key pair")
	}

	// Nil LP checks
	var nilLP *LatestPointer
	if err := nilLP.Sign(dkp.PrivateKey); err == nil {
		t.Fatal("expected error on nilLP.Sign")
	}
	if err := nilLP.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected error on nilLP.Verify")
	}
	if err := nilLP.VerifyWithResolver(NewMockDNSResolver()); err == nil {
		t.Fatal("expected error on nilLP.VerifyWithResolver")
	}
	if err := lp.VerifyWithResolver(nil); err == nil {
		t.Fatal("expected error on lp.VerifyWithResolver(nil)")
	}

	// Sign
	if err := lp.SignWithKeyPair(dkp); err != nil {
		t.Fatalf("failed to sign latest pointer: %v", err)
	}

	// Verify
	if err := lp.Verify(dkp.PublicKey); err != nil {
		t.Fatalf("failed to verify latest pointer: %v", err)
	}

	// DNS Resolver verification
	dns := NewMockDNSResolver()
	_ = dns.SetKey("rfin.ch", dkp.PublicKey)
	if err := lp.VerifyWithResolver(dns); err != nil {
		t.Fatalf("DNS resolver verification failed: %v", err)
	}

	// DNS Resolver verification fail (missing domain)
	dnsEmpty := NewMockDNSResolver()
	if err := lp.VerifyWithResolver(dnsEmpty); err == nil {
		t.Fatal("expected error on missing domain DNS resolver")
	}

	// Tampering tests
	tamperTests := []func(p *LatestPointer){
		func(p *LatestPointer) { p.Tag = "tampered" },
		func(p *LatestPointer) { p.Domain = "tampered.com" },
		func(p *LatestPointer) { p.Package = "tampered-pkg" },
		func(p *LatestPointer) { p.Version = "2.0.0" },
		func(p *LatestPointer) { p.VersionRecordHash = strings.Repeat("d", 64) },
		func(p *LatestPointer) { p.Signature = hex.EncodeToString([]byte("invalid-sig")) },
	}

	for i, tamperFn := range tamperTests {
		clone, _ := NewLatestPointer("rfin.ch", "java-pair", "1.0.0", vrHash)
		_ = clone.SignWithKeyPair(dkp)
		tamperFn(clone)
		if err := clone.Verify(dkp.PublicKey); err == nil {
			t.Errorf("tamper test %d should have failed verification", i)
		}
	}
}

func TestLatestPointer_JSONSerialization_And_LenientKeys(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("rfin.ch")
	vrHash := strings.Repeat("c", 64)
	lp, _ := NewLatestPointer("rfin.ch", "java-pair", "1.0.0", vrHash)
	_ = lp.SignWithKeyPair(dkp)

	// Roundtrip
	data, err := json.Marshal(lp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var lp2 LatestPointer
	if err := json.Unmarshal(data, &lp2); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if lp2 != *lp {
		t.Fatalf("unmarshaled lp %+v != original %+v", lp2, *lp)
	}
	if err := lp2.Verify(dkp.PublicKey); err != nil {
		t.Fatalf("verification failed on unmarshaled lp: %v", err)
	}

	// Nil marshal
	var nilLP *LatestPointer
	if _, err := nilLP.MarshalJSON(); err == nil {
		t.Fatal("expected error on nilLP.MarshalJSON")
	}

	// Bad LP marshal
	badLP := *lp
	badLP.Tag = "bad"
	if _, err := badLP.MarshalJSON(); err == nil {
		t.Fatal("expected error on badLP.MarshalJSON")
	}

	// Lenient unmarshal with snake_case and short keys
	altJSON := `{
		"tag": "latest-pointer",
		"domain_name": "rfin.ch",
		"package_name": "java-pair",
		"version": "1.0.0",
		"version_record_hash": "` + vrHash + `",
		"signature": "` + lp.Signature + `"
	}`
	var lpAlt LatestPointer
	if err := json.Unmarshal([]byte(altJSON), &lpAlt); err != nil {
		t.Fatalf("failed to unmarshal alt JSON: %v", err)
	}
	if err := lpAlt.Verify(dkp.PublicKey); err != nil {
		t.Fatalf("verification failed on alt unmarshaled lp: %v", err)
	}

	// Short key variants: "domain", "package", "sig"
	altJSON2 := `{
		"tag": "latest-pointer",
		"domain": "rfin.ch",
		"package": "java-pair",
		"version": "1.0.0",
		"versionRecordHash": "` + vrHash + `",
		"sig": "` + lp.Signature + `"
	}`
	var lpAlt2 LatestPointer
	if err := json.Unmarshal([]byte(altJSON2), &lpAlt2); err != nil {
		t.Fatalf("failed to unmarshal alt JSON 2: %v", err)
	}
	if lpAlt2.Domain != "rfin.ch" || lpAlt2.Package != "java-pair" {
		t.Fatal("failed to unmarshal short keys on latest pointer")
	}
}

func TestRecordTypeDetectionAndParsing(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("example.com")
	vr, _ := NewVersionRecord("example.com", "my-pkg", "1.0.0", sampleBlobHash(), "")
	_ = vr.SignWithKeyPair(dkp)

	vrBytes, _ := json.Marshal(vr)

	lp, _ := vr.NewLatestPointer()
	_ = lp.SignWithKeyPair(dkp)
	lpBytes, _ := json.Marshal(lp)

	// Detect record type
	if DetectRecordType(vrBytes) != RecordTypeVersionRecord {
		t.Fatalf("expected RecordTypeVersionRecord, got %s", DetectRecordType(vrBytes))
	}
	if DetectRecordType(lpBytes) != RecordTypeLatestPointer {
		t.Fatalf("expected RecordTypeLatestPointer, got %s", DetectRecordType(lpBytes))
	}
	if DetectRecordType([]byte("arbitrary binary payload")) != RecordTypeUnknown {
		t.Fatal("expected RecordTypeUnknown for raw bytes")
	}
	if DetectRecordType([]byte(`{"tag":"random"}`)) != RecordTypeUnknown {
		t.Fatal("expected RecordTypeUnknown for random tag")
	}

	// ParseVersionRecord
	parsedVR, err := ParseVersionRecord(vrBytes)
	if err != nil {
		t.Fatalf("failed to parse version record: %v", err)
	}
	if parsedVR.Version != "1.0.0" {
		t.Fatalf("parsed version mismatch: %s", parsedVR.Version)
	}
	if _, err := ParseVersionRecord([]byte("invalid json")); err == nil {
		t.Fatal("expected error parsing invalid json as VersionRecord")
	}
	badVRJSON := `{"tag":"wrong","domain-name":"example.com","package-name":"pkg","version":"1.0.0","blobHash":"` + sampleBlobHash() + `"}`
	if _, err := ParseVersionRecord([]byte(badVRJSON)); err == nil {
		t.Fatal("expected error parsing invalid VersionRecord")
	}

	// ParseLatestPointer
	parsedLP, err := ParseLatestPointer(lpBytes)
	if err != nil {
		t.Fatalf("failed to parse latest pointer: %v", err)
	}
	if parsedLP.VersionRecordHash != lp.VersionRecordHash {
		t.Fatalf("parsed VR hash mismatch: %s", parsedLP.VersionRecordHash)
	}
	if _, err := ParseLatestPointer([]byte("invalid json")); err == nil {
		t.Fatal("expected error parsing invalid json as LatestPointer")
	}
	badLPJSON := `{"tag":"wrong","domain-name":"rfin.ch","package-name":"pkg","version":"1.0.0","versionRecordHash":"` + strings.Repeat("b", 64) + `"}`
	if _, err := ParseLatestPointer([]byte(badLPJSON)); err == nil {
		t.Fatal("expected error parsing invalid LatestPointer")
	}
}

func TestVersionRecord_EmptyPrevVersionRecord_RoundTripAndHashEquality(t *testing.T) {
	dkp, err := GenerateDomainKeyPair("example.com")
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	blobHash := sampleBlobHash()

	// 1. Create record with literal empty PreviousVersionRecord
	vrEmpty := &VersionRecord{
		Tag:                   TagVersionRecord,
		Domain:                "example.com",
		Package:               "my-pkg",
		Version:               "1.0.0",
		BlobHash:              blobHash,
		PreviousVersionRecord: "",
	}

	if err := vrEmpty.SignWithKeyPair(dkp); err != nil {
		t.Fatalf("failed to sign record with empty prev: %v", err)
	}

	dataEmpty, err := vrEmpty.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal record with empty prev: %v", err)
	}

	// Unmarshal and verify
	vrDeserialized, err := ParseVersionRecord(dataEmpty)
	if err != nil {
		t.Fatalf("failed to unmarshal record: %v", err)
	}
	if err := vrDeserialized.Verify(dkp.PublicKey); err != nil {
		t.Fatalf("verification of unmarshaled record failed: %v", err)
	}

	// 2. Compare with record created with ZeroHash
	vrZero := &VersionRecord{
		Tag:                   TagVersionRecord,
		Domain:                "example.com",
		Package:               "my-pkg",
		Version:               "1.0.0",
		BlobHash:              blobHash,
		PreviousVersionRecord: ZeroHash,
	}
	if err := vrZero.SignWithKeyPair(dkp); err != nil {
		t.Fatalf("failed to sign record with zero hash prev: %v", err)
	}

	hashEmpty, err := vrEmpty.RecordHash()
	if err != nil {
		t.Fatalf("failed to compute hash: %v", err)
	}
	hashDeserialized, err := vrDeserialized.RecordHash()
	if err != nil {
		t.Fatalf("failed to compute hash: %v", err)
	}
	if hashEmpty != hashDeserialized {
		t.Fatalf("RecordHash mismatch after round-trip: %s != %s", hashEmpty, hashDeserialized)
	}

	// Payload hashes should also match
	payHashEmpty, _ := vrEmpty.PayloadHash()
	payHashDeser, _ := vrDeserialized.PayloadHash()
	if payHashEmpty != payHashDeser {
		t.Fatal("PayloadHash mismatch between original and deserialized record")
	}
}

func TestStrictCanonicalValidation(t *testing.T) {
	blobHash := sampleBlobHash()
	validVR, _ := NewVersionRecord("example.com", "my-pkg", "1.0.0", blobHash, ZeroHash)

	// Uppercase hex in BlobHash
	badVR := *validVR
	badVR.BlobHash = strings.ToUpper(blobHash)
	if err := badVR.Validate(); !errors.Is(err, ErrInvalidBlobHash) {
		t.Fatalf("expected ErrInvalidBlobHash for uppercase hex, got %v", err)
	}

	// Uppercase hex in PreviousVersionRecord
	badVR = *validVR
	badVR.PreviousVersionRecord = strings.ToUpper(strings.Repeat("a", 64))
	if err := badVR.Validate(); !errors.Is(err, ErrInvalidRecordHash) {
		t.Fatalf("expected ErrInvalidRecordHash for uppercase prev record, got %v", err)
	}

	// Uppercase domain in VersionRecord
	badVR = *validVR
	badVR.Domain = "EXAMPLE.COM"
	if err := badVR.Validate(); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("expected ErrInvalidDomain for uppercase domain, got %v", err)
	}

	// Uncanonical version in VersionRecord
	badVR = *validVR
	badVR.Version = "v1.0.0"
	if err := badVR.Validate(); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("expected ErrInvalidVersion for non-canonical version, got %v", err)
	}

	// Uppercase hex in LatestPointer VersionRecordHash
	vrHash := strings.Repeat("a", 64)
	validLP, _ := NewLatestPointer("example.com", "my-pkg", "1.0.0", vrHash)

	badLP := *validLP
	badLP.VersionRecordHash = strings.ToUpper(vrHash)
	if err := badLP.Validate(); !errors.Is(err, ErrInvalidRecordHash) {
		t.Fatalf("expected ErrInvalidRecordHash for uppercase VR hash, got %v", err)
	}

	// Uppercase domain in LatestPointer
	badLP = *validLP
	badLP.Domain = "EXAMPLE.COM"
	if err := badLP.Validate(); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("expected ErrInvalidDomain for uppercase domain, got %v", err)
	}

	// Uncanonical version in LatestPointer
	badLP = *validLP
	badLP.Version = "1.0"
	if err := badLP.Validate(); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("expected ErrInvalidVersion for non-canonical version, got %v", err)
	}
}

func TestLatestPointer_HyphenatedWireKey(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("example.com")
	vrHash := strings.Repeat("b", 64)
	lp, _ := NewLatestPointer("example.com", "my-pkg", "1.0.0", vrHash)
	_ = lp.SignWithKeyPair(dkp)

	// JSON with hyphenated version-record-hash
	wireJSON := `{
		"tag": "latest-pointer",
		"domain-name": "example.com",
		"package-name": "my-pkg",
		"version": "1.0.0",
		"version-record-hash": "` + vrHash + `",
		"sig": "` + lp.Signature + `"
	}`

	parsedLP, err := ParseLatestPointer([]byte(wireJSON))
	if err != nil {
		t.Fatalf("failed to parse LatestPointer with hyphenated key: %v", err)
	}
	if parsedLP.VersionRecordHash != vrHash {
		t.Fatalf("expected VersionRecordHash %s, got %s", vrHash, parsedLP.VersionRecordHash)
	}
	if err := parsedLP.Verify(dkp.PublicKey); err != nil {
		t.Fatalf("verification failed for hyphenated key LP: %v", err)
	}
}

func TestRecord_StringAndCrossComparison(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("example.com")
	blobHash := sampleBlobHash()

	vr1, _ := NewVersionRecord("example.com", "my-pkg", "1.0.0", blobHash, ZeroHash)
	_ = vr1.SignWithKeyPair(dkp)

	vr2, _ := NewVersionRecord("example.com", "my-pkg", "2.0.0", blobHash, ZeroHash)
	_ = vr2.SignWithKeyPair(dkp)

	lp1, _ := vr1.NewLatestPointer()
	_ = lp1.SignWithKeyPair(dkp)

	// String() methods
	if !strings.Contains(vr1.String(), "1.0.0") || !strings.Contains(vr1.String(), "example.com") {
		t.Fatalf("unexpected VersionRecord.String output: %s", vr1.String())
	}
	if !strings.Contains(lp1.String(), "1.0.0") || !strings.Contains(lp1.String(), "latest-pointer") {
		t.Fatalf("unexpected LatestPointer.String output: %s", lp1.String())
	}

	var nilVR *VersionRecord
	if nilVR.String() != "<nil VersionRecord>" {
		t.Fatalf("expected nil VersionRecord string, got %s", nilVR.String())
	}
	var nilLP *LatestPointer
	if nilLP.String() != "<nil LatestPointer>" {
		t.Fatalf("expected nil LatestPointer string, got %s", nilLP.String())
	}

	// Cross-comparison
	cmp, err := vr1.CompareVersionWithPointer(lp1)
	if err != nil || cmp != 0 {
		t.Fatalf("expected vr1 == lp1 version, got %d, err=%v", cmp, err)
	}

	cmp, err = lp1.CompareVersionWithRecord(vr2)
	if err != nil || cmp != -1 {
		t.Fatalf("expected lp1 < vr2 version, got %d, err=%v", cmp, err)
	}

	cmp, err = vr2.CompareVersionWithPointer(lp1)
	if err != nil || cmp != 1 {
		t.Fatalf("expected vr2 > lp1 version, got %d, err=%v", cmp, err)
	}

	// Error paths on cross-comparison
	if _, err := nilVR.CompareVersionWithPointer(lp1); err == nil {
		t.Fatal("expected error on nil receiver CompareVersionWithPointer")
	}
	if _, err := vr1.CompareVersionWithPointer(nilLP); err == nil {
		t.Fatal("expected error on nil argument CompareVersionWithPointer")
	}
	if _, err := nilLP.CompareVersionWithRecord(vr1); err == nil {
		t.Fatal("expected error on nil receiver CompareVersionWithRecord")
	}
	if _, err := lp1.CompareVersionWithRecord(nilVR); err == nil {
		t.Fatal("expected error on nil argument CompareVersionWithRecord")
	}
}

func TestLatestPointer_MatchesKeyHelpers(t *testing.T) {
	lp, _ := NewLatestPointer("rfin.ch", "java-pair", "1.0.0", strings.Repeat("c", 64))

	keyHex := lp.DHTKey()
	keyBytes := lp.DHTKeyBytes()

	if !lp.MatchesKey(keyHex) {
		t.Fatal("expected MatchesKey to return true for exact hex key")
	}
	if !lp.MatchesKey(strings.ToUpper(keyHex)) {
		t.Fatal("expected MatchesKey to return true for uppercase hex key")
	}
	if lp.MatchesKey("different-key") {
		t.Fatal("expected MatchesKey to return false for different key")
	}

	if !lp.MatchesKeyBytes(keyBytes) {
		t.Fatal("expected MatchesKeyBytes to return true for exact key bytes")
	}
	if lp.MatchesKeyBytes([32]byte{1, 2, 3}) {
		t.Fatal("expected MatchesKeyBytes to return false for different bytes")
	}

	var nilLP *LatestPointer
	if nilLP.MatchesKey(keyHex) {
		t.Fatal("expected false on nilLP.MatchesKey")
	}
	if nilLP.MatchesKeyBytes(keyBytes) {
		t.Fatal("expected false on nilLP.MatchesKeyBytes")
	}
}

func TestVersionRecord_UnsignedPointerAndMatching(t *testing.T) {
	vr, _ := NewVersionRecord("example.com", "my-pkg", "1.0.0", sampleBlobHash(), "")

	// NewLatestPointer on unsigned VR should fail
	if _, err := vr.NewLatestPointer(); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}

	// MatchesRecord with unsigned VR
	lp, _ := NewLatestPointer("example.com", "my-pkg", "1.0.0", strings.Repeat("d", 64))
	if _, err := lp.MatchesRecord(vr); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature when matching unsigned record, got %v", err)
	}
}
