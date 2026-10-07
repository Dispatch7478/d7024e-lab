package registry

import (
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

	vrInitial, err := NewInitialVersionRecord("example.com", "my-pkg", "1.0.0", blobHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !vrInitial.IsInitialVersion() || vrInitial.PreviousVersionRecord != ZeroHash {
		t.Fatal("expected NewInitialVersionRecord to create an initial record")
	}

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

	// Validation errors on NewVersionRecord
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
		{"example.com", "pkg", "1.0.0", blobHash, "bad-prev", ErrInvalidRecordHash},
	}

	for _, tc := range badCases {
		_, err := NewVersionRecord(tc.domain, tc.pkg, tc.version, tc.blobHash, tc.prev)
		if err == nil || !errors.Is(err, tc.expectErr) {
			t.Errorf("expected error %v, got %v", tc.expectErr, err)
		}
	}

	// Nil receiver validation
	var nilVR *VersionRecord
	if err := nilVR.Validate(); err == nil {
		t.Fatal("expected error on nil record validate")
	}
	if nilVR.IsInitialVersion() {
		t.Fatal("expected false for nilVR.IsInitialVersion()")
	}

	// Invalid tag
	vr1.Tag = "wrong-tag"
	if err := vr1.Validate(); !errors.Is(err, ErrInvalidRecordTag) {
		t.Fatalf("expected ErrInvalidRecordTag, got %v", err)
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
}

func TestVersionRecord_SigningAndVerification(t *testing.T) {
	dkp, err := GenerateDomainKeyPair("example.com")
	if err != nil {
		t.Fatal(err)
	}

	blobHash := sampleBlobHash()
	vr, err := NewVersionRecord("example.com", "my-pkg", "1.0.0", blobHash, "")
	if err != nil {
		t.Fatal(err)
	}

	// Unsigned verify should fail
	if err := vr.Verify(dkp.PublicKey); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}

	// Domain mismatch
	wrongDKP, _ := GenerateDomainKeyPair("other.org")
	if err := vr.SignWithKeyPair(wrongDKP); !errors.Is(err, ErrDomainMismatch) {
		t.Fatalf("expected ErrDomainMismatch, got %v", err)
	}

	// Nil key pair
	if err := vr.SignWithKeyPair(nil); err == nil {
		t.Fatal("expected error signing with nil key pair")
	}

	// Nil record
	var nilVR *VersionRecord
	if err := nilVR.Sign(dkp.PrivateKey); err == nil {
		t.Fatal("expected error on nilVR.Sign")
	}
	if err := nilVR.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected error on nilVR.Verify")
	}
	if err := nilVR.VerifyWithResolver(NewMockDNSResolver()); err == nil {
		t.Fatal("expected error on nilVR.VerifyWithResolver")
	}
	if err := vr.VerifyWithResolver(nil); err == nil {
		t.Fatal("expected error with nil resolver")
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
	_ = dns.SetKey("example.com", dkp.PublicKey)
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

	// Tamper Domain
	vr := makeSignedRecord()
	vr.Domain = "attacker.com"
	if err := vr.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on tampered Domain")
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

	// Unsigned RecordHash should error
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

func TestVersionRecord_JSONSerialization(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("example.com")
	vr, _ := NewVersionRecord("example.com", "my-pkg", "1.0.0", sampleBlobHash(), "")
	_ = vr.SignWithKeyPair(dkp)

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

	var nilVR *VersionRecord
	if _, err := nilVR.MarshalJSON(); err == nil {
		t.Fatal("expected error on nilVR.MarshalJSON")
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

	if LatestPointerKeyString("rfin.ch", "java-pair") != expectedKeyStr {
		t.Fatal("LatestPointerKeyString mismatch")
	}
	if LatestPointerDHTKey("rfin.ch", "java-pair") != expectedHex {
		t.Fatal("LatestPointerDHTKey mismatch")
	}
	if LatestPointerDHTKeyBytes("rfin.ch", "java-pair") != expectedHash {
		t.Fatal("LatestPointerDHTKeyBytes mismatch")
	}

	if !lp.MatchesKey(expectedHex) {
		t.Fatal("MatchesKey failed")
	}
	if !lp.MatchesKeyBytes(expectedHash) {
		t.Fatal("MatchesKeyBytes failed")
	}

	// Nil LP checks
	var nilLP *LatestPointer
	if nilLP.DHTKeyString() != "" || nilLP.DHTKey() != "" {
		t.Fatal("expected empty string on nilLP")
	}
	if nilLP.MatchesKey(expectedHex) || nilLP.MatchesKeyBytes(expectedHash) {
		t.Fatal("expected false on nilLP matches")
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
		{"invalid..domain", "pkg", "1.0.0", vrHash, ErrInvalidDomain},
		{"example.com", "", "1.0.0", vrHash, ErrInvalidPackageName},
		{"example.com", "pkg", "not-a-ver", vrHash, ErrInvalidVersion},
		{"example.com", "pkg", "1.0.0", "short", ErrInvalidRecordHash},
	}
	for _, tc := range badCases {
		if _, err := NewLatestPointer(tc.domain, tc.pkg, tc.version, tc.vrHash); !errors.Is(err, tc.expectErr) {
			t.Errorf("expected error %v, got %v", tc.expectErr, err)
		}
	}
}

func TestLatestPointer_SigningVerificationAndTamper(t *testing.T) {
	dkp, _ := GenerateDomainKeyPair("example.com")
	vrHash := strings.Repeat("c", 64)
	lp, _ := NewLatestPointer("example.com", "my-pkg", "1.0.0", vrHash)

	// Unsigned verify
	if err := lp.Verify(dkp.PublicKey); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}

	// Domain mismatch
	otherDKP, _ := GenerateDomainKeyPair("other.org")
	if err := lp.SignWithKeyPair(otherDKP); !errors.Is(err, ErrDomainMismatch) {
		t.Fatalf("expected ErrDomainMismatch, got %v", err)
	}
	if err := lp.SignWithKeyPair(nil); err == nil {
		t.Fatal("expected error on nil keypair sign")
	}

	// Sign
	if err := lp.SignWithKeyPair(dkp); err != nil {
		t.Fatalf("failed to sign latest pointer: %v", err)
	}
	if err := lp.Verify(dkp.PublicKey); err != nil {
		t.Fatalf("failed to verify latest pointer: %v", err)
	}

	// Verify with resolver
	dns := NewMockDNSResolver()
	_ = dns.SetKey("example.com", dkp.PublicKey)
	if err := lp.VerifyWithResolver(dns); err != nil {
		t.Fatalf("VerifyWithResolver failed: %v", err)
	}

	// Tampered version
	lpTampered := *lp
	lpTampered.Version = "2.0.0"
	if err := lpTampered.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on tampered Version")
	}

	// Tampered VersionRecordHash
	lpTampered = *lp
	lpTampered.VersionRecordHash = strings.Repeat("d", 64)
	if err := lpTampered.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected failure on tampered VersionRecordHash")
	}

	// Marshal/Unmarshal roundtrip
	data, err := json.Marshal(lp)
	if err != nil {
		t.Fatal(err)
	}
	var lp2 LatestPointer
	if err := json.Unmarshal(data, &lp2); err != nil {
		t.Fatal(err)
	}
	if lp2 != *lp {
		t.Fatal("unmarshaled latest pointer mismatch")
	}

	var nilLP *LatestPointer
	if _, err := nilLP.MarshalJSON(); err == nil {
		t.Fatal("expected error on nilLP.MarshalJSON")
	}
	if err := nilLP.Verify(dkp.PublicKey); err == nil {
		t.Fatal("expected error on nilLP.Verify")
	}
	if err := nilLP.VerifyWithResolver(dns); err == nil {
		t.Fatal("expected error on nilLP.VerifyWithResolver")
	}
	if err := lp.VerifyWithResolver(nil); err == nil {
		t.Fatal("expected error on nil resolver")
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

	// DetectRecordType
	if dt := DetectRecordType(vrBytes); dt != RecordTypeVersionRecord {
		t.Fatalf("expected RecordTypeVersionRecord, got %s", dt)
	}
	if dt := DetectRecordType(lpBytes); dt != RecordTypeLatestPointer {
		t.Fatalf("expected RecordTypeLatestPointer, got %s", dt)
	}
	if dt := DetectRecordType([]byte(`{"tag": "unknown"}`)); dt != RecordTypeUnknown {
		t.Fatalf("expected RecordTypeUnknown, got %s", dt)
	}
	if dt := DetectRecordType([]byte(`not json`)); dt != RecordTypeUnknown {
		t.Fatalf("expected RecordTypeUnknown on garbage, got %s", dt)
	}

	// ParseVersionRecord
	parsedVR, err := ParseVersionRecord(vrBytes)
	if err != nil || parsedVR.Version != "1.0.0" {
		t.Fatalf("ParseVersionRecord failed: %v", err)
	}
	if _, err := ParseVersionRecord([]byte(`{"tag": "bad"}`)); err == nil {
		t.Fatal("expected error on bad ParseVersionRecord")
	}

	// ParseLatestPointer
	parsedLP, err := ParseLatestPointer(lpBytes)
	if err != nil || parsedLP.Version != "1.0.0" {
		t.Fatalf("ParseLatestPointer failed: %v", err)
	}
	if _, err := ParseLatestPointer([]byte(`{"tag": "bad"}`)); err == nil {
		t.Fatal("expected error on bad ParseLatestPointer")
	}

	// MatchesRecord
	matches, err := lp.MatchesRecord(vr)
	if err != nil || !matches {
		t.Fatalf("MatchesRecord failed: %v", err)
	}
	var nilVR *VersionRecord
	if _, err := lp.MatchesRecord(nilVR); err == nil {
		t.Fatal("expected error on MatchesRecord with nil VR")
	}
	var nilLP *LatestPointer
	if _, err := nilLP.MatchesRecord(vr); err == nil {
		t.Fatal("expected error on MatchesRecord with nil LP")
	}

	// CompareVersion
	cmp, err := lp.CompareVersion(lp)
	if err != nil || cmp != 0 {
		t.Fatalf("expected CompareVersion 0, got %d, err=%v", cmp, err)
	}
	if _, err := nilLP.CompareVersion(lp); err == nil {
		t.Fatal("expected error comparing nil LP")
	}
	if _, err := lp.CompareVersion(nilLP); err == nil {
		t.Fatal("expected error comparing with nil LP")
	}

	// Strings
	if !strings.Contains(vr.String(), "example.com") {
		t.Fatal("vr.String missing domain")
	}
	if !strings.Contains(lp.String(), "example.com") {
		t.Fatal("lp.String missing domain")
	}
	if nilVR.String() != "<nil VersionRecord>" {
		t.Fatal("unexpected nilVR.String")
	}
	if nilLP.String() != "<nil LatestPointer>" {
		t.Fatal("unexpected nilLP.String")
	}
}
