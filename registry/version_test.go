package registry

import (
	"errors"
	"testing"
)

func TestParseVersion_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected Version
		strRepr  string
	}{
		{"1.0.0", Version{1, 0, 0}, "1.0.0"},
		{"0.0.0", Version{0, 0, 0}, "0.0.0"},
		{"0.1.0", Version{0, 1, 0}, "0.1.0"},
		{"0.0.1", Version{0, 0, 1}, "0.0.1"},
		{"1.2.3", Version{1, 2, 3}, "1.2.3"},
		{"10.20.30", Version{10, 20, 30}, "10.20.30"},
		{"v1.2.3", Version{1, 2, 3}, "1.2.3"},
		{"V2.4.6", Version{2, 4, 6}, "2.4.6"},
		{"  1.2.3  ", Version{1, 2, 3}, "1.2.3"},
		{"1.2", Version{1, 2, 0}, "1.2.0"},
		{"v1.2", Version{1, 2, 0}, "1.2.0"},
		{"1", Version{1, 0, 0}, "1.0.0"},
		{"v1", Version{1, 0, 0}, "1.0.0"},
		{"100.200.300", Version{100, 200, 300}, "100.200.300"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			v, err := ParseVersion(tc.input)
			if err != nil {
				t.Fatalf("unexpected error parsing %q: %v", tc.input, err)
			}
			if v != tc.expected {
				t.Fatalf("expected %+v, got %+v", tc.expected, v)
			}
			if s := v.String(); s != tc.strRepr {
				t.Fatalf("expected string representation %q, got %q", tc.strRepr, s)
			}
		})
	}
}

func TestParseVersion_Invalid(t *testing.T) {
	invalidCases := []string{
		"",
		"   ",
		"v",
		"V",
		"vv1.0.0",
		"vV1.0.0",
		"Vv1.0.0",
		"VV1.0.0",
		"-1.0.0",
		"1.-2.0",
		"1.0.-3",
		"+1.0.0",
		"01.0.0",
		"1.02.0",
		"1.0.03",
		"1..0",
		".1.0",
		"1.0.",
		"..",
		"1.2.3.4",
		"1.2.3.4.5",
		"abc",
		"1.a.0",
		"1.0.z",
		"1.2.3-alpha",
		"1.2.3+build",
		"9999999999999999999999999999999999999999",
	}

	for _, input := range invalidCases {
		t.Run(input, func(t *testing.T) {
			_, err := ParseVersion(input)
			if err == nil {
				t.Fatalf("expected error for invalid version %q, got nil", input)
			}
			if !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("expected ErrInvalidVersion, got: %v", err)
			}
		})
	}
}

func TestVersion_TotalOrdering(t *testing.T) {
	v0 := Version{0, 0, 0}
	v001 := Version{0, 0, 1}
	v010 := Version{0, 1, 0}
	v100 := Version{1, 0, 0}
	v101 := Version{1, 0, 1}
	v102 := Version{1, 0, 2}
	v1010 := Version{1, 0, 10}
	v110 := Version{1, 1, 0}
	v120 := Version{1, 2, 0}
	v200 := Version{2, 0, 0}

	ordered := []Version{v0, v001, v010, v100, v101, v102, v1010, v110, v120, v200}

	// 1. Reflexivity: v.Compare(v) == 0
	for _, v := range ordered {
		if cmp := v.Compare(v); cmp != 0 {
			t.Fatalf("reflexivity failed for %v: Compare returned %d", v, cmp)
		}
		if !v.Equal(v) {
			t.Fatalf("Equal failed for identical version %v", v)
		}
		if v.LessThan(v) || v.GreaterThan(v) {
			t.Fatalf("LessThan or GreaterThan true for identical version %v", v)
		}
	}

	// 2. Strict pairwise ascending order
	for i := 0; i < len(ordered)-1; i++ {
		smaller := ordered[i]
		larger := ordered[i+1]

		if smaller.Compare(larger) != -1 {
			t.Fatalf("expected %v < %v", smaller, larger)
		}
		if larger.Compare(smaller) != 1 {
			t.Fatalf("expected %v > %v", larger, smaller)
		}
		if !smaller.LessThan(larger) {
			t.Fatalf("expected %v.LessThan(%v) to be true", smaller, larger)
		}
		if !larger.GreaterThan(smaller) {
			t.Fatalf("expected %v.GreaterThan(%v) to be true", larger, smaller)
		}
		if smaller.Equal(larger) {
			t.Fatalf("expected %v != %v", smaller, larger)
		}
	}

	// 3. Transitivity: if a < b and b < c, then a < c
	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			for k := j + 1; k < len(ordered); k++ {
				a, b, c := ordered[i], ordered[j], ordered[k]
				if !(a.LessThan(b) && b.LessThan(c) && a.LessThan(c)) {
					t.Fatalf("transitivity failed for %v < %v < %v", a, b, c)
				}
			}
		}
	}

	// 4. Numerical precedence over lexicographical: "1.0.10" > "1.0.2"
	if !v1010.GreaterThan(v102) {
		t.Fatalf("numerical precedence failed: 1.0.10 should be greater than 1.0.2")
	}
}

