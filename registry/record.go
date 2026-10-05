package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Record tag constants as defined in PART2-DESIGN.md.
const (
	// TagVersionRecord is the tag identifying immutable package version records.
	TagVersionRecord = "version-record"
	// TagLatestPointer is the tag identifying mutable latest-version pointers.
	TagLatestPointer = "latest-pointer"
	// ZeroHash is the 64-character hex zero representation used for initial version records.
	ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	// ErrInvalidPackageName indicates that a package name contains invalid characters or structure.
	ErrInvalidPackageName = errors.New("invalid package name")
	// ErrInvalidRecordTag indicates an unexpected or mismatched record tag.
	ErrInvalidRecordTag = errors.New("invalid record tag")
	// ErrInvalidBlobHash indicates that the blob hash is not a 64-character hex SHA-256 string.
	ErrInvalidBlobHash = errors.New("invalid blob hash: must be 64-character hex string")
	// ErrInvalidRecordHash indicates that a record hash is not a 64-character hex SHA-256 string.
	ErrInvalidRecordHash = errors.New("invalid record hash: must be 64-character hex string")
	// ErrMissingSignature indicates that a required digital signature is absent.
	ErrMissingSignature = errors.New("missing signature")
	// ErrDomainMismatch indicates that an operation attempted to use keys from a non-matching domain.
	ErrDomainMismatch = errors.New("domain mismatch")
	// ErrUnknownRecordType indicates that the payload could not be identified as a known record type.
	ErrUnknownRecordType = errors.New("unknown record type")
)

// packageNameRegex enforces safe package naming (alphanumeric with interior hyphens, underscores, dots).
var packageNameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,126}[a-zA-Z0-9])?$`)

// IsValidPackageName reports whether name is a valid package identifier.
func IsValidPackageName(name string) bool {
	pkg := strings.TrimSpace(name)
	if pkg == "" || len(pkg) > 128 {
		return false
	}
	if strings.Contains(pkg, "..") || strings.Contains(pkg, "/") || strings.Contains(pkg, "\\") {
		return false
	}
	return packageNameRegex.MatchString(pkg)
}

func isCanonicalHexHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isValidHexHash(h string) bool {
	return isCanonicalHexHash(strings.ToLower(strings.TrimSpace(h)))
}

// ComputeBlobHash returns the lowercase 64-character hexadecimal SHA-256 hash of arbitrary binary data.
func ComputeBlobHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// VersionRecord represents an immutable package release record stored content-addressably in the DHT.
// {tag="version-record", domain-name, package-name, version, blobHash, previous-version-record, sig}
type VersionRecord struct {
	Tag                   string `json:"tag"`
	Domain                string `json:"domain-name"`
	Package               string `json:"package-name"`
	Version               string `json:"version"`
	BlobHash              string `json:"blobHash"`
	PreviousVersionRecord string `json:"previous-version-record"`
	Signature             string `json:"sig,omitempty"`
}

// NewVersionRecord constructs and validates a new VersionRecord.
// If prevVersionRecord is empty, it defaults to ZeroHash.
func NewVersionRecord(domain, pkg, version, blobHash, prevVersionRecord string) (*VersionRecord, error) {
	normDomain := NormalizeDomain(domain)
	if !IsValidDomain(normDomain) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	normPkg := strings.TrimSpace(pkg)
	if !IsValidPackageName(normPkg) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPackageName, pkg)
	}
	parsedVer, err := ParseVersion(version)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidVersion, err)
	}
	normBlobHash := strings.ToLower(strings.TrimSpace(blobHash))
	if !isValidHexHash(normBlobHash) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidBlobHash, blobHash)
	}
	normPrev := strings.ToLower(strings.TrimSpace(prevVersionRecord))
	if normPrev == "" {
		normPrev = ZeroHash
	} else if normPrev != ZeroHash && !isValidHexHash(normPrev) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidRecordHash, prevVersionRecord)
	}

	return &VersionRecord{
		Tag:                   TagVersionRecord,
		Domain:                normDomain,
		Package:               normPkg,
		Version:               parsedVer.String(),
		BlobHash:              normBlobHash,
		PreviousVersionRecord: normPrev,
	}, nil
}

// NewInitialVersionRecord creates a VersionRecord for the first version of a package,
// pointing to ZeroHash as its previous-version-record.
func NewInitialVersionRecord(domain, pkg, version, blobHash string) (*VersionRecord, error) {
	return NewVersionRecord(domain, pkg, version, blobHash, ZeroHash)
}

func (vr *VersionRecord) normalizedPrev() string {
	if vr == nil || vr.PreviousVersionRecord == "" {
		return ZeroHash
	}
	return vr.PreviousVersionRecord
}

// Validate checks the structural validity of all fields in the VersionRecord.
// Enforces that fields conform to canonical formats.
func (vr *VersionRecord) Validate() error {
	if vr == nil {
		return errors.New("version record is nil")
	}
	if vr.Tag != TagVersionRecord {
		return fmt.Errorf("%w: expected %q, got %q", ErrInvalidRecordTag, TagVersionRecord, vr.Tag)
	}
	if vr.Domain != NormalizeDomain(vr.Domain) || !IsValidDomain(vr.Domain) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, vr.Domain)
	}
	if vr.Package != strings.TrimSpace(vr.Package) || !IsValidPackageName(vr.Package) {
		return fmt.Errorf("%w: %q", ErrInvalidPackageName, vr.Package)
	}
	parsedVer, err := ParseVersion(vr.Version)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidVersion, err)
	}
	if vr.Version != parsedVer.String() {
		return fmt.Errorf("%w: %q is not canonical %q", ErrInvalidVersion, vr.Version, parsedVer.String())
	}
	if !isCanonicalHexHash(vr.BlobHash) {
		return fmt.Errorf("%w: %q", ErrInvalidBlobHash, vr.BlobHash)
	}
	if vr.PreviousVersionRecord == "" {
		vr.PreviousVersionRecord = ZeroHash
	} else if vr.PreviousVersionRecord != ZeroHash && !isCanonicalHexHash(vr.PreviousVersionRecord) {
		return fmt.Errorf("%w: %q", ErrInvalidRecordHash, vr.PreviousVersionRecord)
	}
	return nil
}

// IsInitialVersion returns true if this record represents the initial version (previous record is empty or ZeroHash).
func (vr *VersionRecord) IsInitialVersion() bool {
	if vr == nil {
		return false
	}
	return vr.PreviousVersionRecord == "" || vr.PreviousVersionRecord == ZeroHash
}

// ParsedVersion returns the parsed Version struct for this record.
func (vr *VersionRecord) ParsedVersion() (Version, error) {
	if vr == nil {
		return Version{}, errors.New("version record is nil")
	}
	return ParseVersion(vr.Version)
}

// CompareVersion compares the version of vr with other (-1, 0, 1).
func (vr *VersionRecord) CompareVersion(other *VersionRecord) (int, error) {
	if vr == nil || other == nil {
		return 0, errors.New("version record is nil")
	}
	v1, err := vr.ParsedVersion()
	if err != nil {
		return 0, err
	}
	v2, err := other.ParsedVersion()
	if err != nil {
		return 0, err
	}
	return v1.Compare(v2), nil
}

// CompareVersionWithPointer compares vr's version with the latest pointer's version (-1, 0, 1).
func (vr *VersionRecord) CompareVersionWithPointer(lp *LatestPointer) (int, error) {
	if vr == nil || lp == nil {
		return 0, errors.New("version record or latest pointer is nil")
	}
	v1, err := vr.ParsedVersion()
	if err != nil {
		return 0, err
	}
	v2, err := lp.ParsedVersion()
	if err != nil {
		return 0, err
	}
	return v1.Compare(v2), nil
}

// String returns a concise human-readable summary of the VersionRecord for CLI and logs.
func (vr *VersionRecord) String() string {
	if vr == nil {
		return "<nil VersionRecord>"
	}
	blobShort := vr.BlobHash
	if len(blobShort) > 8 {
		blobShort = blobShort[:8]
	}
	prevShort := vr.PreviousVersionRecord
	if len(prevShort) > 8 {
		prevShort = prevShort[:8]
	}
	return fmt.Sprintf("[version-record] %s:%s@%s (blob: %s..., prev: %s...)",
		vr.Domain, vr.Package, vr.Version, blobShort, prevShort)
}

type versionRecordCanonicalPayload struct {
	Tag                   string `json:"tag"`
	Domain                string `json:"domain-name"`
	Package               string `json:"package-name"`
	Version               string `json:"version"`
	BlobHash              string `json:"blobHash"`
	PreviousVersionRecord string `json:"previous-version-record"`
}

// CanonicalBytes returns the deterministic JSON bytes of the version record payload (excluding signature).
func (vr *VersionRecord) CanonicalBytes() ([]byte, error) {
	if err := vr.Validate(); err != nil {
		return nil, err
	}
	payload := versionRecordCanonicalPayload{
		Tag:                   vr.Tag,
		Domain:                vr.Domain,
		Package:               vr.Package,
		Version:               vr.Version,
		BlobHash:              vr.BlobHash,
		PreviousVersionRecord: vr.normalizedPrev(),
	}
	return json.Marshal(payload)
}

// PayloadHash returns the 32-byte SHA-256 digest of the canonical payload.
func (vr *VersionRecord) PayloadHash() ([32]byte, error) {
	b, err := vr.CanonicalBytes()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// PayloadHashHex returns the 64-character hexadecimal SHA-256 digest of the canonical payload.
func (vr *VersionRecord) PayloadHashHex() (string, error) {
	h, err := vr.PayloadHash()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h[:]), nil
}

// Sign signs the canonical payload hash using the domain owner's private key.
func (vr *VersionRecord) Sign(priv ed25519.PrivateKey) error {
	if vr == nil {
		return errors.New("version record is nil")
	}
	h, err := vr.PayloadHash()
	if err != nil {
		return err
	}
	sig, err := Sign(priv, h[:])
	if err != nil {
		return err
	}
	vr.Signature = EncodeSignatureHex(sig)
	return nil
}

// SignWithKeyPair signs the version record after validating that the key pair belongs to the record's domain.
func (vr *VersionRecord) SignWithKeyPair(dkp *DomainKeyPair) error {
	if dkp == nil {
		return errors.New("domain key pair is nil")
	}
	if NormalizeDomain(dkp.Domain) != vr.Domain {
		return fmt.Errorf("%w: key pair domain %q does not match record domain %q", ErrDomainMismatch, dkp.Domain, vr.Domain)
	}
	return vr.Sign(dkp.PrivateKey)
}

// Verify verifies the digital signature of the version record against the provided public key.
func (vr *VersionRecord) Verify(pub ed25519.PublicKey) error {
	if vr == nil {
		return errors.New("version record is nil")
	}
	if vr.Signature == "" {
		return ErrMissingSignature
	}
	sigBytes, err := ParseSignature(vr.Signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}
	h, err := vr.PayloadHash()
	if err != nil {
		return err
	}
	return Verify(pub, h[:], sigBytes)
}

// VerifyWithResolver resolves the owner public key via DNS and verifies the record signature.
func (vr *VersionRecord) VerifyWithResolver(resolver DNSResolver) error {
	if resolver == nil {
		return errors.New("dns resolver is nil")
	}
	if vr == nil {
		return errors.New("version record is nil")
	}
	pub, err := resolver.LookupOwnerKey(vr.Domain)
	if err != nil {
		return fmt.Errorf("failed to resolve owner key for %q: %w", vr.Domain, err)
	}
	return vr.Verify(pub)
}

// RecordHashBytes returns the 32-byte SHA-256 digest of the serialized VersionRecord (content-addressable DHT key).
func (vr *VersionRecord) RecordHashBytes() ([32]byte, error) {
	if vr == nil {
		return [32]byte{}, errors.New("version record is nil")
	}
	if vr.Signature == "" {
		return [32]byte{}, ErrMissingSignature
	}
	data, err := vr.MarshalJSON()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// RecordHash returns the 64-character hexadecimal SHA-256 digest of the serialized VersionRecord.
func (vr *VersionRecord) RecordHash() (string, error) {
	h, err := vr.RecordHashBytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h[:]), nil
}

type versionRecordWire struct {
	Tag                   string `json:"tag"`
	Domain                string `json:"domain-name"`
	Package               string `json:"package-name"`
	Version               string `json:"version"`
	BlobHash              string `json:"blobHash"`
	PreviousVersionRecord string `json:"previous-version-record"`
	Signature             string `json:"sig,omitempty"`
}

// MarshalJSON serializes the VersionRecord into standard deterministic JSON.
func (vr *VersionRecord) MarshalJSON() ([]byte, error) {
	if vr == nil {
		return nil, errors.New("cannot marshal nil VersionRecord")
	}
	if err := vr.Validate(); err != nil {
		return nil, err
	}
	wire := versionRecordWire{
		Tag:                   vr.Tag,
		Domain:                vr.Domain,
		Package:               vr.Package,
		Version:               vr.Version,
		BlobHash:              vr.BlobHash,
		PreviousVersionRecord: vr.normalizedPrev(),
		Signature:             vr.Signature,
	}
	return json.Marshal(wire)
}

// UnmarshalJSON deserializes a VersionRecord from JSON, accepting hyphenated, snake_case, or camelCase keys.
func (vr *VersionRecord) UnmarshalJSON(data []byte) error {
	var aux struct {
		Tag                   string `json:"tag"`
		Domain                string `json:"domain-name"`
		DomainSnake           string `json:"domain_name"`
		DomainShort           string `json:"domain"`
		Package               string `json:"package-name"`
		PackageSnake          string `json:"package_name"`
		PackageShort          string `json:"package"`
		Version               string `json:"version"`
		BlobHash              string `json:"blobHash"`
		BlobHashSnake         string `json:"blob_hash"`
		PreviousVersionRecord string `json:"previous-version-record"`
		PrevSnake             string `json:"previous_version_record"`
		PrevShort             string `json:"prev_version_record"`
		Sig                   string `json:"sig"`
		Signature             string `json:"signature"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	domain := aux.Domain
	if domain == "" {
		if aux.DomainSnake != "" {
			domain = aux.DomainSnake
		} else {
			domain = aux.DomainShort
		}
	}

	pkg := aux.Package
	if pkg == "" {
		if aux.PackageSnake != "" {
			pkg = aux.PackageSnake
		} else {
			pkg = aux.PackageShort
		}
	}

	blobHash := aux.BlobHash
	if blobHash == "" {
		blobHash = aux.BlobHashSnake
	}

	prev := aux.PreviousVersionRecord
	if prev == "" {
		if aux.PrevSnake != "" {
			prev = aux.PrevSnake
		} else {
			prev = aux.PrevShort
		}
	}
	if prev == "" {
		prev = ZeroHash
	}

	sig := aux.Sig
	if sig == "" {
		sig = aux.Signature
	}

	vr.Tag = aux.Tag
	vr.Domain = NormalizeDomain(domain)
	vr.Package = strings.TrimSpace(pkg)
	if v, err := ParseVersion(aux.Version); err == nil {
		vr.Version = v.String()
	} else {
		vr.Version = strings.TrimSpace(aux.Version)
	}
	vr.BlobHash = strings.ToLower(strings.TrimSpace(blobHash))
	vr.PreviousVersionRecord = strings.ToLower(strings.TrimSpace(prev))
	vr.Signature = strings.TrimSpace(sig)

	return vr.Validate()
}

// NewLatestPointer constructs a LatestPointer that points to this VersionRecord.
func (vr *VersionRecord) NewLatestPointer() (*LatestPointer, error) {
	if vr == nil {
		return nil, errors.New("version record is nil")
	}
	vrHash, err := vr.RecordHash()
	if err != nil {
		return nil, fmt.Errorf("failed to compute version record hash: %w", err)
	}
	return NewLatestPointer(vr.Domain, vr.Package, vr.Version, vrHash)
}

// LatestPointer represents a mutable pointer to the latest package version record in the DHT.
// {tag="latest-pointer", domain-name, package-name, version, versionRecordHash, sig}
type LatestPointer struct {
	Tag               string `json:"tag"`
	Domain            string `json:"domain-name"`
	Package           string `json:"package-name"`
	Version           string `json:"version"`
	VersionRecordHash string `json:"versionRecordHash"`
	Signature         string `json:"sig,omitempty"`
}

// NewLatestPointer constructs and validates a new LatestPointer.
func NewLatestPointer(domain, pkg, version, versionRecordHash string) (*LatestPointer, error) {
	normDomain := NormalizeDomain(domain)
	if !IsValidDomain(normDomain) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	normPkg := strings.TrimSpace(pkg)
	if !IsValidPackageName(normPkg) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPackageName, pkg)
	}
	parsedVer, err := ParseVersion(version)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidVersion, err)
	}
	normVRHash := strings.ToLower(strings.TrimSpace(versionRecordHash))
	if !isValidHexHash(normVRHash) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidRecordHash, versionRecordHash)
	}

	return &LatestPointer{
		Tag:               TagLatestPointer,
		Domain:            normDomain,
		Package:           normPkg,
		Version:           parsedVer.String(),
		VersionRecordHash: normVRHash,
	}, nil
}

// Validate checks the structural validity of all fields in the LatestPointer.
// Enforces that fields conform to canonical formats.
func (lp *LatestPointer) Validate() error {
	if lp == nil {
		return errors.New("latest pointer is nil")
	}
	if lp.Tag != TagLatestPointer {
		return fmt.Errorf("%w: expected %q, got %q", ErrInvalidRecordTag, TagLatestPointer, lp.Tag)
	}
	if lp.Domain != NormalizeDomain(lp.Domain) || !IsValidDomain(lp.Domain) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, lp.Domain)
	}
	if lp.Package != strings.TrimSpace(lp.Package) || !IsValidPackageName(lp.Package) {
		return fmt.Errorf("%w: %q", ErrInvalidPackageName, lp.Package)
	}
	parsedVer, err := ParseVersion(lp.Version)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidVersion, err)
	}
	if lp.Version != parsedVer.String() {
		return fmt.Errorf("%w: %q is not canonical %q", ErrInvalidVersion, lp.Version, parsedVer.String())
	}
	if !isCanonicalHexHash(lp.VersionRecordHash) {
		return fmt.Errorf("%w: %q", ErrInvalidRecordHash, lp.VersionRecordHash)
	}
	return nil
}

// ParsedVersion returns the parsed Version struct for this latest pointer.
func (lp *LatestPointer) ParsedVersion() (Version, error) {
	if lp == nil {
		return Version{}, errors.New("latest pointer is nil")
	}
	return ParseVersion(lp.Version)
}

// CompareVersion compares the version of lp with other (-1, 0, 1).
func (lp *LatestPointer) CompareVersion(other *LatestPointer) (int, error) {
	if lp == nil || other == nil {
		return 0, errors.New("latest pointer is nil")
	}
	v1, err := lp.ParsedVersion()
	if err != nil {
		return 0, err
	}
	v2, err := other.ParsedVersion()
	if err != nil {
		return 0, err
	}
	return v1.Compare(v2), nil
}

type latestPointerCanonicalPayload struct {
	Tag               string `json:"tag"`
	Domain            string `json:"domain-name"`
	Package           string `json:"package-name"`
	Version           string `json:"version"`
	VersionRecordHash string `json:"versionRecordHash"`
}

// CanonicalBytes returns the deterministic JSON bytes of the latest pointer payload (excluding signature).
func (lp *LatestPointer) CanonicalBytes() ([]byte, error) {
	if err := lp.Validate(); err != nil {
		return nil, err
	}
	payload := latestPointerCanonicalPayload{
		Tag:               lp.Tag,
		Domain:            lp.Domain,
		Package:           lp.Package,
		Version:           lp.Version,
		VersionRecordHash: lp.VersionRecordHash,
	}
	return json.Marshal(payload)
}

// PayloadHash returns the 32-byte SHA-256 digest of the canonical payload.
func (lp *LatestPointer) PayloadHash() ([32]byte, error) {
	b, err := lp.CanonicalBytes()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// PayloadHashHex returns the 64-character hexadecimal SHA-256 digest of the canonical payload.
func (lp *LatestPointer) PayloadHashHex() (string, error) {
	h, err := lp.PayloadHash()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h[:]), nil
}

// Sign signs the canonical payload hash using the domain owner's private key.
func (lp *LatestPointer) Sign(priv ed25519.PrivateKey) error {
	if lp == nil {
		return errors.New("latest pointer is nil")
	}
	h, err := lp.PayloadHash()
	if err != nil {
		return err
	}
	sig, err := Sign(priv, h[:])
	if err != nil {
		return err
	}
	lp.Signature = EncodeSignatureHex(sig)
	return nil
}

// SignWithKeyPair signs the latest pointer after validating that the key pair belongs to the pointer's domain.
func (lp *LatestPointer) SignWithKeyPair(dkp *DomainKeyPair) error {
	if dkp == nil {
		return errors.New("domain key pair is nil")
	}
	if NormalizeDomain(dkp.Domain) != lp.Domain {
		return fmt.Errorf("%w: key pair domain %q does not match pointer domain %q", ErrDomainMismatch, dkp.Domain, lp.Domain)
	}
	return lp.Sign(dkp.PrivateKey)
}

// Verify verifies the digital signature of the latest pointer against the provided public key.
func (lp *LatestPointer) Verify(pub ed25519.PublicKey) error {
	if lp == nil {
		return errors.New("latest pointer is nil")
	}
	if lp.Signature == "" {
		return ErrMissingSignature
	}
	sigBytes, err := ParseSignature(lp.Signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}
	h, err := lp.PayloadHash()
	if err != nil {
		return err
	}
	return Verify(pub, h[:], sigBytes)
}

// VerifyWithResolver resolves the owner public key via DNS and verifies the latest pointer signature.
func (lp *LatestPointer) VerifyWithResolver(resolver DNSResolver) error {
	if resolver == nil {
		return errors.New("dns resolver is nil")
	}
	if lp == nil {
		return errors.New("latest pointer is nil")
	}
	pub, err := resolver.LookupOwnerKey(lp.Domain)
	if err != nil {
		return fmt.Errorf("failed to resolve owner key for %q: %w", lp.Domain, err)
	}
	return lp.Verify(pub)
}

// LatestPointerKeyString returns the literal string "domain:package:latest".
func LatestPointerKeyString(domain, pkg string) string {
	return fmt.Sprintf("%s:%s:latest", NormalizeDomain(domain), strings.TrimSpace(pkg))
}

// LatestPointerDHTKeyBytes returns the 32-byte SHA-256 hash of "domain:package:latest".
func LatestPointerDHTKeyBytes(domain, pkg string) [32]byte {
	return sha256.Sum256([]byte(LatestPointerKeyString(domain, pkg)))
}

// LatestPointerDHTKey returns the 64-character hexadecimal SHA-256 hash of "domain:package:latest".
func LatestPointerDHTKey(domain, pkg string) string {
	h := LatestPointerDHTKeyBytes(domain, pkg)
	return hex.EncodeToString(h[:])
}

// DHTKeyString returns "domain:package:latest" for this latest pointer.
func (lp *LatestPointer) DHTKeyString() string {
	if lp == nil {
		return ""
	}
	return LatestPointerKeyString(lp.Domain, lp.Package)
}

// DHTKeyBytes returns the 32-byte SHA-256 DHT key for this latest pointer.
func (lp *LatestPointer) DHTKeyBytes() [32]byte {
	if lp == nil {
		return [32]byte{}
	}
	return LatestPointerDHTKeyBytes(lp.Domain, lp.Package)
}

// DHTKey returns the 64-character hexadecimal SHA-256 DHT key for this latest pointer.
func (lp *LatestPointer) DHTKey() string {
	if lp == nil {
		return ""
	}
	return LatestPointerDHTKey(lp.Domain, lp.Package)
}

// MatchesRecord verifies that this latest pointer corresponds to the given VersionRecord.
func (lp *LatestPointer) MatchesRecord(vr *VersionRecord) (bool, error) {
	if lp == nil || vr == nil {
		return false, errors.New("latest pointer or version record is nil")
	}
	if lp.Domain != vr.Domain {
		return false, nil
	}
	if lp.Package != vr.Package {
		return false, nil
	}
	if lp.Version != vr.Version {
		return false, nil
	}
	vrHash, err := vr.RecordHash()
	if err != nil {
		return false, err
	}
	return lp.VersionRecordHash == vrHash, nil
}

// CompareVersionWithRecord compares lp's version with the version record's version (-1, 0, 1).
func (lp *LatestPointer) CompareVersionWithRecord(vr *VersionRecord) (int, error) {
	if lp == nil || vr == nil {
		return 0, errors.New("latest pointer or version record is nil")
	}
	v1, err := lp.ParsedVersion()
	if err != nil {
		return 0, err
	}
	v2, err := vr.ParsedVersion()
	if err != nil {
		return 0, err
	}
	return v1.Compare(v2), nil
}

// MatchesKey reports whether key matches this latest pointer's DHT key.
func (lp *LatestPointer) MatchesKey(key string) bool {
	if lp == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(key), lp.DHTKey())
}

// MatchesKeyBytes reports whether key matches this latest pointer's 32-byte DHT key.
func (lp *LatestPointer) MatchesKeyBytes(key [32]byte) bool {
	if lp == nil {
		return false
	}
	return lp.DHTKeyBytes() == key
}

// String returns a concise human-readable summary of the LatestPointer for CLI and logs.
func (lp *LatestPointer) String() string {
	if lp == nil {
		return "<nil LatestPointer>"
	}
	recShort := lp.VersionRecordHash
	if len(recShort) > 8 {
		recShort = recShort[:8]
	}
	return fmt.Sprintf("[latest-pointer] %s:%s@%s -> %s...",
		lp.Domain, lp.Package, lp.Version, recShort)
}

type latestPointerWire struct {
	Tag               string `json:"tag"`
	Domain            string `json:"domain-name"`
	Package           string `json:"package-name"`
	Version           string `json:"version"`
	VersionRecordHash string `json:"versionRecordHash"`
	Signature         string `json:"sig,omitempty"`
}

// MarshalJSON serializes the LatestPointer into standard deterministic JSON.
func (lp *LatestPointer) MarshalJSON() ([]byte, error) {
	if lp == nil {
		return nil, errors.New("cannot marshal nil LatestPointer")
	}
	if err := lp.Validate(); err != nil {
		return nil, err
	}
	wire := latestPointerWire{
		Tag:               lp.Tag,
		Domain:            lp.Domain,
		Package:           lp.Package,
		Version:           lp.Version,
		VersionRecordHash: lp.VersionRecordHash,
		Signature:         lp.Signature,
	}
	return json.Marshal(wire)
}

// UnmarshalJSON deserializes a LatestPointer from JSON, accepting hyphenated, snake_case, or camelCase keys.
func (lp *LatestPointer) UnmarshalJSON(data []byte) error {
	var aux struct {
		Tag              string `json:"tag"`
		Domain           string `json:"domain-name"`
		DomainSnake      string `json:"domain_name"`
		DomainShort      string `json:"domain"`
		Package          string `json:"package-name"`
		PackageSnake     string `json:"package_name"`
		PackageShort     string `json:"package"`
		Version          string `json:"version"`
		VersionRecHash   string `json:"versionRecordHash"`
		VersionRecSnake  string `json:"version_record_hash"`
		VersionRecHyphen string `json:"version-record-hash"`
		Sig              string `json:"sig"`
		Signature        string `json:"signature"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	domain := aux.Domain
	if domain == "" {
		if aux.DomainSnake != "" {
			domain = aux.DomainSnake
		} else {
			domain = aux.DomainShort
		}
	}

	pkg := aux.Package
	if pkg == "" {
		if aux.PackageSnake != "" {
			pkg = aux.PackageSnake
		} else {
			pkg = aux.PackageShort
		}
	}

	vrHash := aux.VersionRecHash
	if vrHash == "" {
		if aux.VersionRecSnake != "" {
			vrHash = aux.VersionRecSnake
		} else {
			vrHash = aux.VersionRecHyphen
		}
	}

	sig := aux.Sig
	if sig == "" {
		sig = aux.Signature
	}

	lp.Tag = aux.Tag
	lp.Domain = NormalizeDomain(domain)
	lp.Package = strings.TrimSpace(pkg)
	if v, err := ParseVersion(aux.Version); err == nil {
		lp.Version = v.String()
	} else {
		lp.Version = strings.TrimSpace(aux.Version)
	}
	lp.VersionRecordHash = strings.ToLower(strings.TrimSpace(vrHash))
	lp.Signature = strings.TrimSpace(sig)

	return lp.Validate()
}

// RecordType represents the detected discriminator tag of a DHT record.
type RecordType string

const (
	// RecordTypeUnknown denotes an unrecognized payload or non-record blob.
	RecordTypeUnknown RecordType = "unknown"
	// RecordTypeVersionRecord denotes a VersionRecord payload.
	RecordTypeVersionRecord RecordType = "version-record"
	// RecordTypeLatestPointer denotes a LatestPointer payload.
	RecordTypeLatestPointer RecordType = "latest-pointer"
)

// DetectRecordType examines the JSON tag in raw bytes without full unmarshaling.
func DetectRecordType(data []byte) RecordType {
	var tagProbe struct {
		Tag string `json:"tag"`
	}
	if err := json.Unmarshal(data, &tagProbe); err != nil {
		return RecordTypeUnknown
	}
	switch tagProbe.Tag {
	case TagVersionRecord:
		return RecordTypeVersionRecord
	case TagLatestPointer:
		return RecordTypeLatestPointer
	default:
		return RecordTypeUnknown
	}
}

// ParseVersionRecord parses and validates a VersionRecord from JSON bytes.
func ParseVersionRecord(data []byte) (*VersionRecord, error) {
	var vr VersionRecord
	if err := json.Unmarshal(data, &vr); err != nil {
		return nil, err
	}
	if err := vr.Validate(); err != nil {
		return nil, err
	}
	return &vr, nil
}

// ParseLatestPointer parses and validates a LatestPointer from JSON bytes.
func ParseLatestPointer(data []byte) (*LatestPointer, error) {
	var lp LatestPointer
	if err := json.Unmarshal(data, &lp); err != nil {
		return nil, err
	}
	if err := lp.Validate(); err != nil {
		return nil, err
	}
	return &lp, nil
}
