package registry

import (
	"encoding/json"
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

func TestCompareVersions(t *testing.T) {
	cmp, err := CompareVersions("1.2.3", "1.2.4")
	if err != nil || cmp != -1 {
		t.Fatalf("expected -1, got %d, err=%v", cmp, err)
	}

	cmp, err = CompareVersions("2.0.0", "1.9.9")
	if err != nil || cmp != 1 {
		t.Fatalf("expected 1, got %d, err=%v", cmp, err)
	}

	cmp, err = CompareVersions("v1.0.0", "1.0.0")
	if err != nil || cmp != 0 {
		t.Fatalf("expected 0, got %d, err=%v", cmp, err)
	}

	// First invalid
	_, err = CompareVersions("invalid", "1.0.0")
	if err == nil {
		t.Fatal("expected error on invalid first version")
	}

	// Second invalid
	_, err = CompareVersions("1.0.0", "invalid")
	if err == nil {
		t.Fatal("expected error on invalid second version")
	}
}

func TestSortVersions_And_SortVersionStrings(t *testing.T) {
	raw := []string{"2.0.0", "0.1.0", "1.0.0", "1.10.0", "1.2.0", "0.0.1"}
	expectedSorted := []string{"0.0.1", "0.1.0", "1.0.0", "1.2.0", "1.10.0", "2.0.0"}

	sorted, err := SortVersionStrings(raw)
	if err != nil {
		t.Fatalf("unexpected sort error: %v", err)
	}
	for i, s := range sorted {
		if s != expectedSorted[i] {
			t.Fatalf("at index %d: expected %s, got %s", i, expectedSorted[i], s)
		}
	}

	// Error path
	_, err = SortVersionStrings([]string{"1.0.0", "invalid"})
	if err == nil {
		t.Fatal("expected error when sorting slice with invalid version")
	}

	// SortVersions directly
	vers := []Version{
		{2, 0, 0},
		{0, 1, 0},
		{1, 0, 0},
	}
	SortVersions(vers)
	if vers[0] != (Version{0, 1, 0}) || vers[1] != (Version{1, 0, 0}) || vers[2] != (Version{2, 0, 0}) {
		t.Fatalf("SortVersions produced incorrect order: %+v", vers)
	}
}

func TestVersion_JSONAndTextMarshaling(t *testing.T) {
	v := Version{Major: 1, Minor: 2, Patch: 3}

	// JSON Marshal
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	if string(data) != `"1.2.3"` {
		t.Fatalf("expected JSON %q, got %q", `"1.2.3"`, string(data))
	}

	// JSON Unmarshal
	var v2 Version
	if err := json.Unmarshal(data, &v2); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if v2 != v {
		t.Fatalf("unmarshaled version %+v != %+v", v2, v)
	}

	// JSON Unmarshal invalid
	var v3 Version
	if err := json.Unmarshal([]byte(`"not-a-version"`), &v3); err == nil {
		t.Fatal("expected error unmarshaling invalid version string")
	}
	if err := json.Unmarshal([]byte(`123`), &v3); err == nil {
		t.Fatal("expected error unmarshaling non-string JSON")
	}

	// Text Marshal
	text, err := v.MarshalText()
	if err != nil {
		t.Fatalf("failed to marshal text: %v", err)
	}
	if string(text) != "1.2.3" {
		t.Fatalf("expected text %q, got %q", "1.2.3", string(text))
	}

	// Text Unmarshal
	var v4 Version
	if err := v4.UnmarshalText(text); err != nil {
		t.Fatalf("failed to unmarshal text: %v", err)
	}
	if v4 != v {
		t.Fatalf("unmarshaled text version %+v != %+v", v4, v)
	}

	// Text Unmarshal invalid
	if err := v4.UnmarshalText([]byte("bad")); err == nil {
		t.Fatal("expected error unmarshaling bad text")
	}
}
