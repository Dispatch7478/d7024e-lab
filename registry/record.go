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

const (
	TagVersionRecord = "version-record"
	TagLatestPointer = "latest-pointer"
	ZeroHash         = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	ErrInvalidPackageName = errors.New("invalid package name")
	ErrInvalidRecordTag   = errors.New("invalid record tag")
	ErrInvalidBlobHash    = errors.New("invalid blob hash: must be 64-character hex string")
	ErrInvalidRecordHash  = errors.New("invalid record hash: must be 64-character hex string")
	ErrMissingSignature   = errors.New("missing signature")
	ErrDomainMismatch     = errors.New("domain mismatch")
	ErrUnknownRecordType  = errors.New("unknown record type")
	packageNameRegex      = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,126}[a-zA-Z0-9])?$`)
)

func IsValidPackageName(name string) bool {
	pkg := strings.TrimSpace(name)
	return pkg != "" && len(pkg) <= 128 && !strings.Contains(pkg, "..") && packageNameRegex.MatchString(pkg)
}

func ComputeBlobHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

type VersionRecord struct {
	Tag                   string `json:"tag"`
	Domain                string `json:"domain-name"`
	Package               string `json:"package-name"`
	Version               string `json:"version"`
	BlobHash              string `json:"blobHash"`
	PreviousVersionRecord string `json:"previous-version-record"`
	Signature             string `json:"sig,omitempty"`
}

func NewVersionRecord(domain, pkg, version, blobHash, prevVR string) (*VersionRecord, error) {
	normDomain := NormalizeDomain(domain)
	if !IsValidDomain(normDomain) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	normPkg := strings.TrimSpace(pkg)
	if !IsValidPackageName(normPkg) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPackageName, pkg)
	}
	v, err := ParseVersion(version)
	if err != nil {
		return nil, err
	}
	normBlobHash := strings.ToLower(strings.TrimSpace(blobHash))
	if len(normBlobHash) != 64 {
		return nil, fmt.Errorf("%w: %q", ErrInvalidBlobHash, blobHash)
	}
	normPrev := strings.ToLower(strings.TrimSpace(prevVR))
	if normPrev == "" {
		normPrev = ZeroHash
	} else if len(normPrev) != 64 {
		return nil, fmt.Errorf("%w: %q", ErrInvalidRecordHash, prevVR)
	}
	return &VersionRecord{
		Tag: TagVersionRecord, Domain: normDomain, Package: normPkg,
		Version: v.String(), BlobHash: normBlobHash, PreviousVersionRecord: normPrev,
	}, nil
}

func NewInitialVersionRecord(domain, pkg, version, blobHash string) (*VersionRecord, error) {
	return NewVersionRecord(domain, pkg, version, blobHash, ZeroHash)
}

func (vr *VersionRecord) Validate() error {
	if vr == nil {
		return errors.New("nil record")
	}
	if vr.Tag != TagVersionRecord {
		return fmt.Errorf("%w: %q", ErrInvalidRecordTag, vr.Tag)
	}
	if !IsValidDomain(vr.Domain) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, vr.Domain)
	}
	if !IsValidPackageName(vr.Package) {
		return fmt.Errorf("%w: %q", ErrInvalidPackageName, vr.Package)
	}
	if _, err := ParseVersion(vr.Version); err != nil {
		return err
	}
	if len(vr.BlobHash) != 64 {
		return fmt.Errorf("%w: %q", ErrInvalidBlobHash, vr.BlobHash)
	}
	if vr.PreviousVersionRecord == "" {
		vr.PreviousVersionRecord = ZeroHash
	} else if len(vr.PreviousVersionRecord) != 64 {
		return fmt.Errorf("%w: %q", ErrInvalidRecordHash, vr.PreviousVersionRecord)
	}
	return nil
}

func (vr *VersionRecord) payloadBytes() ([]byte, error) {
	if err := vr.Validate(); err != nil {
		return nil, err
	}
	cp := *vr
	cp.Signature = ""
	return json.Marshal(cp)
}

func (vr *VersionRecord) Sign(priv ed25519.PrivateKey) error {
	if vr == nil {
		return errors.New("nil record")
	}
	data, err := vr.payloadBytes()
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	sig, _ := Sign(priv, h[:])
	vr.Signature = EncodeSignatureHex(sig)
	return nil
}

func (vr *VersionRecord) SignWithKeyPair(dkp *DomainKeyPair) error {
	if dkp == nil {
		return errors.New("nil key pair")
	}
	if NormalizeDomain(dkp.Domain) != vr.Domain {
		return fmt.Errorf("%w: domain mismatch", ErrDomainMismatch)
	}
	return vr.Sign(dkp.PrivateKey)
}

func (vr *VersionRecord) Verify(pub ed25519.PublicKey) error {
	if vr == nil {
		return errors.New("nil record")
	}
	if vr.Signature == "" {
		return ErrMissingSignature
	}
	sig, err := DecodeSignatureHex(vr.Signature)
	if err != nil {
		return err
	}
	data, err := vr.payloadBytes()
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	return Verify(pub, h[:], sig)
}

func (vr *VersionRecord) VerifyWithResolver(resolver DNSResolver) error {
	if resolver == nil || vr == nil {
		return errors.New("nil resolver or record")
	}
	pub, err := resolver.LookupOwnerKey(vr.Domain)
	if err != nil {
		return err
	}
	return vr.Verify(pub)
}

func (vr *VersionRecord) MarshalJSON() ([]byte, error) {
	if vr == nil {
		return nil, errors.New("cannot marshal nil")
	}
	type wire VersionRecord
	return json.Marshal((*wire)(vr))
}

func (vr *VersionRecord) RecordHashBytes() ([32]byte, error) {
	if vr == nil || vr.Signature == "" {
		return [32]byte{}, ErrMissingSignature
	}
	data, err := json.Marshal(vr)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

func (vr *VersionRecord) RecordHash() (string, error) {
	h, err := vr.RecordHashBytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h[:]), nil
}

func (vr *VersionRecord) DHTKey() (string, error) { return vr.RecordHash() }

func (vr *VersionRecord) ParsedVersion() (Version, error) {
	if vr == nil {
		return Version{}, errors.New("nil record")
	}
	return ParseVersion(vr.Version)
}

func (vr *VersionRecord) CompareVersion(other *VersionRecord) (int, error) {
	if vr == nil || other == nil {
		return 0, errors.New("nil record")
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

func (vr *VersionRecord) IsInitialVersion() bool {
	return vr != nil && (vr.PreviousVersionRecord == "" || vr.PreviousVersionRecord == ZeroHash)
}

func (vr *VersionRecord) NewLatestPointer() (*LatestPointer, error) {
	if vr == nil {
		return nil, errors.New("nil record")
	}
	h, err := vr.RecordHash()
	if err != nil {
		return nil, err
	}
	return NewLatestPointer(vr.Domain, vr.Package, vr.Version, h)
}

func (vr *VersionRecord) String() string {
	if vr == nil {
		return "<nil VersionRecord>"
	}
	return fmt.Sprintf("[version-record] %s:%s@%s", vr.Domain, vr.Package, vr.Version)
}

type LatestPointer struct {
	Tag               string `json:"tag"`
	Domain            string `json:"domain-name"`
	Package           string `json:"package-name"`
	Version           string `json:"version"`
	VersionRecordHash string `json:"versionRecordHash"`
	Signature         string `json:"sig,omitempty"`
}

func NewLatestPointer(domain, pkg, version, vrHash string) (*LatestPointer, error) {
	normDomain := NormalizeDomain(domain)
	if !IsValidDomain(normDomain) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	normPkg := strings.TrimSpace(pkg)
	if !IsValidPackageName(normPkg) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPackageName, pkg)
	}
	v, err := ParseVersion(version)
	if err != nil {
		return nil, err
	}
	normVRHash := strings.ToLower(strings.TrimSpace(vrHash))
	if len(normVRHash) != 64 {
		return nil, fmt.Errorf("%w: %q", ErrInvalidRecordHash, vrHash)
	}
	return &LatestPointer{
		Tag: TagLatestPointer, Domain: normDomain, Package: normPkg,
		Version: v.String(), VersionRecordHash: normVRHash,
	}, nil
}

func (lp *LatestPointer) Validate() error {
	if lp == nil {
		return errors.New("nil pointer")
	}
	if lp.Tag != TagLatestPointer {
		return fmt.Errorf("%w: %q", ErrInvalidRecordTag, lp.Tag)
	}
	if !IsValidDomain(lp.Domain) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, lp.Domain)
	}
	if !IsValidPackageName(lp.Package) {
		return fmt.Errorf("%w: %q", ErrInvalidPackageName, lp.Package)
	}
	if _, err := ParseVersion(lp.Version); err != nil {
		return err
	}
	if len(lp.VersionRecordHash) != 64 {
		return fmt.Errorf("%w: %q", ErrInvalidRecordHash, lp.VersionRecordHash)
	}
	return nil
}

func (lp *LatestPointer) payloadBytes() ([]byte, error) {
	if err := lp.Validate(); err != nil {
		return nil, err
	}
	cp := *lp
	cp.Signature = ""
	return json.Marshal(cp)
}

func (lp *LatestPointer) Sign(priv ed25519.PrivateKey) error {
	if lp == nil {
		return errors.New("nil pointer")
	}
	data, err := lp.payloadBytes()
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	sig, _ := Sign(priv, h[:])
	lp.Signature = EncodeSignatureHex(sig)
	return nil
}

func (lp *LatestPointer) SignWithKeyPair(dkp *DomainKeyPair) error {
	if dkp == nil {
		return errors.New("nil key pair")
	}
	if NormalizeDomain(dkp.Domain) != lp.Domain {
		return fmt.Errorf("%w: domain mismatch", ErrDomainMismatch)
	}
	return lp.Sign(dkp.PrivateKey)
}

func (lp *LatestPointer) Verify(pub ed25519.PublicKey) error {
	if lp == nil {
		return errors.New("nil pointer")
	}
	if lp.Signature == "" {
		return ErrMissingSignature
	}
	sig, err := DecodeSignatureHex(lp.Signature)
	if err != nil {
		return err
	}
	data, err := lp.payloadBytes()
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	return Verify(pub, h[:], sig)
}

func (lp *LatestPointer) VerifyWithResolver(resolver DNSResolver) error {
	if resolver == nil || lp == nil {
		return errors.New("nil resolver or pointer")
	}
	pub, err := resolver.LookupOwnerKey(lp.Domain)
	if err != nil {
		return err
	}
	return lp.Verify(pub)
}

func (lp *LatestPointer) MarshalJSON() ([]byte, error) {
	if lp == nil {
		return nil, errors.New("cannot marshal nil")
	}
	type wire LatestPointer
	return json.Marshal((*wire)(lp))
}

func LatestPointerKeyString(domain, pkg string) string {
	return NormalizeDomain(domain) + ":" + strings.TrimSpace(pkg) + ":latest"
}
func LatestPointerDHTKeyBytes(domain, pkg string) [32]byte {
	return sha256.Sum256([]byte(LatestPointerKeyString(domain, pkg)))
}
func LatestPointerDHTKey(domain, pkg string) string {
	h := LatestPointerDHTKeyBytes(domain, pkg)
	return hex.EncodeToString(h[:])
}

func (lp *LatestPointer) DHTKeyString() string {
	if lp == nil {
		return ""
	}
	return LatestPointerKeyString(lp.Domain, lp.Package)
}
func (lp *LatestPointer) DHTKeyBytes() [32]byte {
	if lp == nil {
		return [32]byte{}
	}
	return LatestPointerDHTKeyBytes(lp.Domain, lp.Package)
}
func (lp *LatestPointer) DHTKey() string {
	if lp == nil {
		return ""
	}
	return LatestPointerDHTKey(lp.Domain, lp.Package)
}
func (lp *LatestPointer) ParsedVersion() (Version, error) {
	if lp == nil {
		return Version{}, errors.New("nil pointer")
	}
	return ParseVersion(lp.Version)
}
func (lp *LatestPointer) CompareVersion(other *LatestPointer) (int, error) {
	if lp == nil || other == nil {
		return 0, errors.New("nil pointer")
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
func (lp *LatestPointer) MatchesRecord(vr *VersionRecord) (bool, error) {
	if lp == nil || vr == nil {
		return false, errors.New("nil pointer or record")
	}
	h, err := vr.RecordHash()
	if err != nil {
		return false, err
	}
	return lp.Domain == vr.Domain && lp.Package == vr.Package && lp.Version == vr.Version && lp.VersionRecordHash == h, nil
}
func (lp *LatestPointer) MatchesKey(key string) bool {
	return lp != nil && strings.EqualFold(strings.TrimSpace(key), lp.DHTKey())
}
func (lp *LatestPointer) MatchesKeyBytes(key [32]byte) bool {
	return lp != nil && lp.DHTKeyBytes() == key
}
func (lp *LatestPointer) String() string {
	if lp == nil {
		return "<nil LatestPointer>"
	}
	return fmt.Sprintf("[latest-pointer] %s:%s@%s -> %s", lp.Domain, lp.Package, lp.Version, lp.VersionRecordHash)
}

type RecordType string

const (
	RecordTypeUnknown       RecordType = "unknown"
	RecordTypeVersionRecord RecordType = "version-record"
	RecordTypeLatestPointer RecordType = "latest-pointer"
)

func DetectRecordType(data []byte) RecordType {
	var probe struct {
		Tag string `json:"tag"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return RecordTypeUnknown
	}
	switch probe.Tag {
	case TagVersionRecord:
		return RecordTypeVersionRecord
	case TagLatestPointer:
		return RecordTypeLatestPointer
	default:
		return RecordTypeUnknown
	}
}

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
