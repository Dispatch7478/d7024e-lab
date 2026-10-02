package main

import (
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSliceHelpers(t *testing.T) {
	ints, err := parseInts("10, 20, 30")
	if err != nil || len(ints) != 3 || ints[0] != 10 || ints[2] != 30 {
		t.Fatalf("unexpected ints: %v, err: %v", ints, err)
	}

	if _, err := parseInts("invalid"); err == nil {
		t.Errorf("expected error for invalid int")
	}

	int64s, err := parseInt64s("100, 200")
	if err != nil || len(int64s) != 2 || int64s[0] != 100 || int64s[1] != 200 {
		t.Fatalf("unexpected int64s: %v, err: %v", int64s, err)
	}

	if _, err := parseInt64s("abc"); err == nil {
		t.Errorf("expected error for invalid int64")
	}

	floats, err := parseFloats("0.1, 0.25")
	if err != nil || len(floats) != 2 || floats[0] != 0.1 || floats[1] != 0.25 {
		t.Fatalf("unexpected floats: %v, err: %v", floats, err)
	}

	if _, err := parseFloats("xyz"); err == nil {
		t.Errorf("expected error for invalid float")
	}

	// Empty and whitespace edge cases
	emptyInts, err := parseInts("  , , ")
	if err != nil || len(emptyInts) != 0 {
		t.Errorf("expected empty slice for empty string, got %v, err: %v", emptyInts, err)
	}
}

func TestValidateConfig(t *testing.T) {
	validScalability := config{
		mode:     "scalability",
		sizes:    []int{50, 100},
		seeds:    []int64{101},
		lookups:  10,
		alpha:    3,
		relNodes: 50,
	}
	if err := validateConfig(validScalability); err != nil {
		t.Errorf("unexpected error for valid scalability config: %v", err)
	}

	validReliability := config{
		mode:      "reliability",
		lossRates: []float64{0.0, 0.2},
		seeds:     []int64{101},
		lookups:   10,
		alpha:     3,
		relNodes:  50,
	}
	if err := validateConfig(validReliability); err != nil {
		t.Errorf("unexpected error for valid reliability config: %v", err)
	}

	validAll := config{
		mode:      "all",
		sizes:     []int{50},
		lossRates: []float64{0.1},
		seeds:     []int64{101},
		lookups:   5,
		alpha:     3,
		relNodes:  50,
	}
	if err := validateConfig(validAll); err != nil {
		t.Errorf("unexpected error for valid 'all' config: %v", err)
	}

	testCases := []struct {
		name string
		cfg  config
	}{
		{"empty seeds", config{seeds: []int64{}, lookups: 10, alpha: 3, mode: "all"}},
		{"lookups zero", config{seeds: []int64{1}, lookups: 0, alpha: 3, mode: "all"}},
		{"alpha negative", config{seeds: []int64{1}, lookups: 10, alpha: -1, mode: "all"}},
		{"unknown mode", config{seeds: []int64{1}, lookups: 10, alpha: 3, mode: "invalid"}},
		{"empty sizes in scalability", config{seeds: []int64{1}, lookups: 10, alpha: 3, mode: "scalability", sizes: []int{}}},
		{"negative size in scalability", config{seeds: []int64{1}, lookups: 10, alpha: 3, mode: "scalability", sizes: []int{50, -1}}},
		{"zero relNodes in reliability", config{seeds: []int64{1}, lookups: 10, alpha: 3, mode: "reliability", relNodes: 0, lossRates: []float64{0.1}}},
		{"empty loss in reliability", config{seeds: []int64{1}, lookups: 10, alpha: 3, mode: "reliability", relNodes: 50, lossRates: []float64{}}},
		{"negative loss", config{seeds: []int64{1}, lookups: 10, alpha: 3, mode: "reliability", relNodes: 50, lossRates: []float64{-0.1}}},
		{"loss greater than 1", config{seeds: []int64{1}, lookups: 10, alpha: 3, mode: "reliability", relNodes: 50, lossRates: []float64{1.5}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateConfig(tc.cfg); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestBuildNetworkAndRandomID(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	id := randomID(rng)
	if id == nil {
		t.Fatalf("expected non-nil random ID")
	}

	handler := slog.New(slog.DiscardHandler).Handler()
	hub, nodes := buildNetwork(5, 101, 3, handler)
	if hub == nil || len(nodes) != 5 {
		t.Fatalf("expected 5 nodes and non-nil hub, got %d nodes", len(nodes))
	}
}

func TestRunExperiments(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test_simulation.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("failed to create log file: %v", err)
	}
	defer logFile.Close()

	handler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug})

	// Run small scalability
	runScalability([]int{5, 10}, []int64{101}, 2, 3, handler)

	// Run small reliability
	runReliability(5, []float64{0.0, 0.1}, []int64{101}, 2, 3, handler)

	info, err := os.Stat(logPath)
	if err != nil || info.Size() == 0 {
		t.Fatalf("expected non-empty log file, got size: %d, err: %v", info.Size(), err)
	}
}
