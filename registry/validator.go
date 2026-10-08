package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUnauthorized         = errors.New("unauthorized: domain owner verification failed")
	ErrVersionRollback      = errors.New("version rollback rejected: version must be strictly greater than current version")
	ErrHistoryFork          = errors.New("history fork rejected: version chain does not link back to current version record")
	ErrMissingVersionRecord = errors.New("missing version record in history chain")
	ErrCorruptRecord        = errors.New("corrupted version record")
	ErrInvalidHistoryChain  = errors.New("invalid version history chain")
	ErrNoDNSResolver        = errors.New("dns resolver is required to validate latest pointer")
	ErrInvalidLatestPointer = errors.New("invalid latest pointer record")
)

const DefaultMaxChainDepth = 1000

type RecordGetter func(hash string) ([]byte, error)
type RecordSaver func(hash string, data []byte)

type PackageValidator struct {
	Resolver      DNSResolver
	Getter        RecordGetter
	Saver         RecordSaver
	MaxChainDepth int
}

func NewPackageValidator(resolver DNSResolver, getter RecordGetter, saver ...RecordSaver) *PackageValidator {
	var s RecordSaver
	if len(saver) > 0 {
		s = saver[0]
	}
	return &PackageValidator{Resolver: resolver, Getter: getter, Saver: s, MaxChainDepth: DefaultMaxChainDepth}
}

func (pv *PackageValidator) ValidatePublication(lp *LatestPointer, existingLP *LatestPointer) error {
	if pv == nil {
		return errors.New("package validator is nil")
	}
	depth := pv.MaxChainDepth
	if depth <= 0 {
		depth = DefaultMaxChainDepth
	}
	return ValidateLatestPointerChainWithDepth(lp, existingLP, pv.Resolver, pv.Getter, pv.Saver, depth)
}

func ValidateLatestPointerChain(lp *LatestPointer, existingLP *LatestPointer, resolver DNSResolver, getter RecordGetter, saver RecordSaver) error {
	return ValidateLatestPointerChainWithDepth(lp, existingLP, resolver, getter, saver, DefaultMaxChainDepth)
}

func ValidateLatestPointerChainWithDepth(
	lp *LatestPointer,
	existingLP *LatestPointer,
	resolver DNSResolver,
	getter RecordGetter,
	saver RecordSaver,
	maxDepth int,
) error {
	if lp == nil {
		return ErrInvalidLatestPointer
	}
	if err := lp.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidLatestPointer, err)
	}
	if strings.EqualFold(strings.TrimSpace(lp.VersionRecordHash), ZeroHash) {
		return fmt.Errorf("%w: latest pointer cannot reference ZeroHash", ErrInvalidLatestPointer)
	}
	if resolver == nil {
		return ErrNoDNSResolver
	}
	ownerPub, err := resolver.LookupOwnerKey(lp.Domain)
	if err != nil {
		return fmt.Errorf("%w: owner lookup for domain %q failed: %v", ErrUnauthorized, lp.Domain, err)
	}
	if err := lp.Verify(ownerPub); err != nil {
		return fmt.Errorf("%w: invalid signature on latest pointer: %v", ErrUnauthorized, err)
	}

	targetRecordHash := ZeroHash
	if existingLP != nil {
		if err := existingLP.Validate(); err != nil {
			return fmt.Errorf("existing latest pointer invalid: %w", err)
		}
		if strings.EqualFold(strings.TrimSpace(existingLP.VersionRecordHash), ZeroHash) {
			return fmt.Errorf("%w: existing latest pointer cannot reference ZeroHash", ErrInvalidLatestPointer)
		}
		if existingLP.Domain != lp.Domain || existingLP.Package != lp.Package {
			return fmt.Errorf("%w: domain/pkg mismatch (%s/%s vs %s/%s)", ErrDomainMismatch, existingLP.Domain, existingLP.Package, lp.Domain, lp.Package)
		}
		cmp, err := lp.CompareVersion(existingLP)
		if err != nil {
			return fmt.Errorf("version comparison failed: %w", err)
		}
		if cmp <= 0 {
			return fmt.Errorf("%w: version %s is not strictly greater than %s", ErrVersionRollback, lp.Version, existingLP.Version)
		}
		targetRecordHash = existingLP.VersionRecordHash
		if strings.EqualFold(lp.VersionRecordHash, targetRecordHash) {
			return fmt.Errorf("%w: latest pointer references existing record hash", ErrHistoryFork)
		}
	}

	if getter == nil {
		return fmt.Errorf("%w: record getter is nil", ErrMissingVersionRecord)
	}
	if maxDepth <= 0 {
		maxDepth = DefaultMaxChainDepth
	}

	normTarget := strings.ToLower(strings.TrimSpace(targetRecordHash))
	currentHash := strings.ToLower(strings.TrimSpace(lp.VersionRecordHash))
	visited := make(map[string]bool)
	isHead := true
	var lastParsedVer Version

	type pendingSave struct {
		hash string
		data []byte
	}
	var toSave []pendingSave

	for currentHash != normTarget {
		if currentHash == ZeroHash {
			if existingLP != nil {
				return fmt.Errorf("%w: chain terminated at ZeroHash without linking to %s", ErrHistoryFork, existingLP.VersionRecordHash)
			}
			break
		}
		if visited[currentHash] {
			return fmt.Errorf("%w: cycle detected at %s", ErrInvalidHistoryChain, currentHash)
		}
		visited[currentHash] = true
		if len(visited) > maxDepth {
			return fmt.Errorf("%w: maximum history chain depth exceeded", ErrInvalidHistoryChain)
		}

		recBytes, err := getter(currentHash)
		if err != nil || len(recBytes) == 0 {
			return fmt.Errorf("%w: failed to retrieve record %s", ErrMissingVersionRecord, currentHash)
		}
		recHash := sha256.Sum256(recBytes)
		if hex.EncodeToString(recHash[:]) != currentHash {
			return fmt.Errorf("%w: hash mismatch for record %s", ErrCorruptRecord, currentHash)
		}
		vr, err := ParseVersionRecord(recBytes)
		if err != nil {
			return fmt.Errorf("%w: parse error on %s: %v", ErrCorruptRecord, currentHash, err)
		}
		if vr.Domain != lp.Domain || vr.Package != lp.Package {
			return fmt.Errorf("%w: record %s domain/pkg (%s/%s) does not match pointer (%s/%s)", ErrDomainMismatch, currentHash, vr.Domain, vr.Package, lp.Domain, lp.Package)
		}
		if err := vr.Verify(ownerPub); err != nil {
			return fmt.Errorf("%w: invalid owner signature on record %s: %v", ErrUnauthorized, currentHash, err)
		}
		vrVer, err := vr.ParsedVersion()
		if err != nil {
			return fmt.Errorf("failed to parse version on record %s: %w", currentHash, err)
		}

		if isHead {
			if vr.Version != lp.Version {
				return fmt.Errorf("%w: pointer version %s does not match head record version %s", ErrInvalidHistoryChain, lp.Version, vr.Version)
			}
			isHead = false
		} else {
			if lastParsedVer.Compare(vrVer) <= 0 {
				return fmt.Errorf("%w: non-monotonic version in chain (%s -> %s)", ErrInvalidHistoryChain, lastParsedVer.String(), vrVer.String())
			}
		}
		lastParsedVer = vrVer
		toSave = append(toSave, pendingSave{hash: currentHash, data: recBytes})

		prev := strings.ToLower(strings.TrimSpace(vr.PreviousVersionRecord))
		if prev == "" {
			prev = ZeroHash
		}
		currentHash = prev
	}

	if existingLP != nil {
		existingVer, err := existingLP.ParsedVersion()
		if err != nil {
			return fmt.Errorf("failed to parse existing version: %w", err)
		}
		if lastParsedVer.Compare(existingVer) <= 0 {
			return fmt.Errorf("%w: chain predecessor version %s is not strictly greater than existing version %s", ErrInvalidHistoryChain, lastParsedVer.String(), existingVer.String())
		}
	}

	if saver != nil {
		for _, item := range toSave {
			saver(item.hash, item.data)
		}
	}
	return nil
}

func WalkVersionChain(headHash string, getter RecordGetter) ([]*VersionRecord, error) {
	return WalkVersionChainWithDepth(headHash, getter, DefaultMaxChainDepth)
}

func WalkVersionChainWithDepth(headHash string, getter RecordGetter, maxDepth int) ([]*VersionRecord, error) {
	if getter == nil {
		return nil, errors.New("record getter is nil")
	}
	if maxDepth <= 0 {
		maxDepth = DefaultMaxChainDepth
	}
	normHead := strings.ToLower(strings.TrimSpace(headHash))
	if normHead == "" || normHead == ZeroHash {
		return nil, nil
	}

	var chain []*VersionRecord
	visited := make(map[string]bool)
	currentHash := normHead

	for currentHash != "" && currentHash != ZeroHash {
		if visited[currentHash] {
			return chain, fmt.Errorf("%w: cycle detected at %s", ErrInvalidHistoryChain, currentHash)
		}
		visited[currentHash] = true
		if len(visited) > maxDepth {
			return chain, fmt.Errorf("%w: max chain depth %d exceeded", ErrInvalidHistoryChain, maxDepth)
		}
		data, err := getter(currentHash)
		if err != nil || len(data) == 0 {
			return chain, fmt.Errorf("%w: %s", ErrMissingVersionRecord, currentHash)
		}
		expectedHash := sha256.Sum256(data)
		if hex.EncodeToString(expectedHash[:]) != currentHash {
			return chain, fmt.Errorf("%w: hash mismatch for record %s", ErrCorruptRecord, currentHash)
		}
		vr, err := ParseVersionRecord(data)
		if err != nil {
			return chain, fmt.Errorf("%w: failed to parse %s: %v", ErrCorruptRecord, currentHash, err)
		}
		chain = append(chain, vr)
		prev := strings.ToLower(strings.TrimSpace(vr.PreviousVersionRecord))
		if prev == "" {
			prev = ZeroHash
		}
		currentHash = prev
	}
	return chain, nil
}
