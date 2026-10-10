package registry

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrInvalidVersion indicates that a version string does not conform to the required format.
	ErrInvalidVersion = errors.New("invalid version string")
)

// Version represents a semantic version consisting of Major, Minor, and Patch numbers.
// Versions have a strict total ordering: Major > Minor > Patch.
type Version struct {
	Major uint64
	Minor uint64
	Patch uint64
}

// ParseVersion parses a string into a Version struct.
// It supports standard semantic versioning (e.g. "1.2.3"), optional leading 'v' or 'V'
// (e.g. "v1.2.3"), and allows 1 to 3 numeric components (e.g. "1.2" -> 1.2.0, "1" -> 1.0.0).
// Leading zeros on multi-digit numbers (like "01") are rejected to avoid octal/decimal ambiguities.
func ParseVersion(s string) (Version, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return Version{}, ErrInvalidVersion
	}

	if strings.HasPrefix(trimmed, "v") || strings.HasPrefix(trimmed, "V") {
		trimmed = trimmed[1:]
	}
	if trimmed == "" {
		return Version{}, fmt.Errorf("%w: empty version after prefix in %q", ErrInvalidVersion, s)
	}

	parts := strings.Split(trimmed, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return Version{}, fmt.Errorf("%w: %q (expected 1 to 3 dot-separated integers)", ErrInvalidVersion, s)
	}

	nums := make([]uint64, 3)
	for i, part := range parts {
		if part == "" {
			return Version{}, fmt.Errorf("%w: empty component in %q", ErrInvalidVersion, s)
		}
		// Disallow leading zeros for numbers greater than 0
		if len(part) > 1 && part[0] == '0' {
			return Version{}, fmt.Errorf("%w: leading zero not allowed in %q", ErrInvalidVersion, s)
		}
		// Verify all characters are digits (prevents signs like '+' or '-')
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return Version{}, fmt.Errorf("%w: non-numeric character in %q", ErrInvalidVersion, s)
			}
		}
		num, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("%w: %v in %q", ErrInvalidVersion, err, s)
		}
		nums[i] = num
	}

	return Version{
		Major: nums[0],
		Minor: nums[1],
		Patch: nums[2],
	}, nil
}

// String returns the normalized canonical string representation "Major.Minor.Patch".
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare returns:
//
//	-1 if v < other
//	 0 if v == other
//	 1 if v > other
//
// Comparison follows strict total ordering: Major first, then Minor, then Patch.
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// LessThan reports whether v < other.
func (v Version) LessThan(other Version) bool {
	return v.Compare(other) < 0
}

// GreaterThan reports whether v > other.
func (v Version) GreaterThan(other Version) bool {
	return v.Compare(other) > 0
}

// Equal reports whether v == other.
func (v Version) Equal(other Version) bool {
	return v.Compare(other) == 0
}
