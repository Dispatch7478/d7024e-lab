package main

import (
	"flag"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"d7024e/kademlia"
)

type config struct {
	mode      string
	sizes     []int
	lossRates []float64
	seeds     []int64
	lookups   int
	alpha     int
	relNodes  int
}

func validateConfig(cfg config) error {
	if len(cfg.seeds) == 0 {
		return fmt.Errorf("at least one seed must be provided")
	}
	if cfg.lookups <= 0 {
		return fmt.Errorf("lookups must be > 0, got %d", cfg.lookups)
	}
	if cfg.alpha <= 0 {
		return fmt.Errorf("alpha must be > 0, got %d", cfg.alpha)
	}

	mode := strings.ToLower(cfg.mode)
	if mode != "scalability" && mode != "reliability" && mode != "all" {
		return fmt.Errorf("unknown mode: %s. Use 'scalability', 'reliability', or 'all'", cfg.mode)
	}

	if mode == "scalability" || mode == "all" {
		if len(cfg.sizes) == 0 {
			return fmt.Errorf("at least one network size must be provided for scalability")
		}
		for _, s := range cfg.sizes {
			if s <= 0 {
				return fmt.Errorf("network size must be > 0, got %d", s)
			}
		}
	}

	if mode == "reliability" || mode == "all" {
		if cfg.relNodes <= 0 {
			return fmt.Errorf("rel-nodes must be > 0, got %d", cfg.relNodes)
		}
		if len(cfg.lossRates) == 0 {
			return fmt.Errorf("at least one loss rate must be provided for reliability")
		}
		for _, l := range cfg.lossRates {
			if l < 0.0 || l > 1.0 {
				return fmt.Errorf("packet loss rate must be between 0.0 and 1.0, got %f", l)
			}
		}
	}

	return nil
}

func main() {
	mode := flag.String("mode", "all", "Experiment mode: 'scalability', 'reliability', or 'all'")
	sizesFlag := flag.String("sizes", "50,100,200,500,1000", "Comma-separated network sizes N for scalability")
	lossFlag := flag.String("loss", "0.0,0.10,0.20,0.30,0.40,0.50,0.60,0.70,0.80,0.85,0.90", "Comma-separated packet loss rates for reliability")
	seedsFlag := flag.String("seeds", "101,202,303", "Comma-separated RNG seeds for statistical variance")
	lookupsFlag := flag.Int("lookups", 25, "Number of lookups per seed run")
	alphaFlag := flag.Int("alpha", 3, "Parallelism factor alpha")
	relNodesFlag := flag.Int("rel-nodes", 100, "Network size for reliability experiment")
	outPath := flag.String("out", "data/simulation.log", "Output path for structured simulation log")
	appendFlag := flag.Bool("append", false, "Append to log file instead of truncating")
	flag.Parse()

	seeds, err := parseInt64s(*seedsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing seeds: %v\n", err)
		os.Exit(1)
	}

	var sizes []int
	var lossRates []float64

	modeLower := strings.ToLower(*mode)
	if modeLower == "scalability" || modeLower == "all" {
		sizes, err = parseInts(*sizesFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing sizes: %v\n", err)
			os.Exit(1)
		}
	}

	if modeLower == "reliability" || modeLower == "all" {
		lossRates, err = parseFloats(*lossFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing loss rates: %v\n", err)
			os.Exit(1)
		}
	}

	cfg := config{
		mode:      *mode,
		sizes:     sizes,
		lossRates: lossRates,
		seeds:     seeds,
		lookups:   *lookupsFlag,
		alpha:     *alphaFlag,
		relNodes:  *relNodesFlag,
	}

	if err := validateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output dir: %v\n", err)
		os.Exit(1)
	}

	openFlags := os.O_CREATE | os.O_WRONLY
	if *appendFlag {
		openFlags |= os.O_APPEND
	} else {
		openFlags |= os.O_TRUNC
	}

	logFile, err := os.OpenFile(*outPath, openFlags, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	logHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(logHandler))

	switch modeLower {
	case "scalability":
		runScalability(sizes, seeds, *lookupsFlag, *alphaFlag, logHandler)
	case "reliability":
		runReliability(*relNodesFlag, lossRates, seeds, *lookupsFlag, *alphaFlag, logHandler)
	case "all":
		runScalability(sizes, seeds, *lookupsFlag, *alphaFlag, logHandler)
		fmt.Println()
		runReliability(*relNodesFlag, lossRates, seeds, *lookupsFlag, *alphaFlag, logHandler)
	}

	fmt.Printf("\nSimulation completed. Logs written to: %s\n", *outPath)
}

func runScalability(sizes []int, seeds []int64, lookups, alpha int, logHandler slog.Handler) {
	fmt.Println("================================================================================")
	fmt.Printf("EXPERIMENT 1: Lookup Scalability vs Network Size N\n")
	fmt.Printf("Sizes: %v | Seeds: %v | Lookups/seed: %d | Alpha: %d\n", sizes, seeds, lookups, alpha)
	fmt.Println("================================================================================")

	for _, n := range sizes {
		fmt.Printf("Running N=%-5d across %d seeds... ", n, len(seeds))
		for _, seed := range seeds {
			_, nodes := buildNetwork(n, seed, alpha, logHandler)
			queryRng := rand.New(rand.NewSource(seed + int64(n)*1000))

			for trial := 0; trial < lookups; trial++ {
				qIdx := queryRng.Intn(n)
				target := randomID(queryRng)

				slog.Info("starting lookup",
					"event", "lookup_start",
					"experiment", "scalability",
					"n", n,
					"loss", 0.0,
					"seed", seed,
					"trial", trial,
					"alpha", alpha,
					"target", target.String(),
				)
				nodes[qIdx].LookupContactByID(target)
			}
		}
		fmt.Println("done.")
	}
}

func runReliability(n int, lossRates []float64, seeds []int64, lookups, alpha int, logHandler slog.Handler) {
	fmt.Println("================================================================================")
	fmt.Printf("EXPERIMENT 2: Lookup Reliability vs Packet Loss Rate (N=%d)\n", n)
	fmt.Printf("Loss: %v | Seeds: %v | Lookups/seed: %d | Alpha: %d\n", lossRates, seeds, lookups, alpha)
	fmt.Println("================================================================================")

	for _, loss := range lossRates {
		fmt.Printf("Running Loss=%-5.1f%% across %d seeds... ", loss*100, len(seeds))
		for _, seed := range seeds {
			hub, nodes := buildNetwork(n, seed, alpha, logHandler)
			hub.SetPacketLoss(loss)
			queryRng := rand.New(rand.NewSource(seed + int64(math.Round(loss*100000))))

			for trial := 0; trial < lookups; trial++ {
				qIdx := queryRng.Intn(n)
				target := randomID(queryRng)

				slog.Info("starting lookup",
					"event", "lookup_start",
					"experiment", "reliability",
					"n", n,
					"loss", loss,
					"seed", seed,
					"trial", trial,
					"alpha", alpha,
					"target", target.String(),
				)
				nodes[qIdx].LookupContactByID(target)
			}
		}
		fmt.Println("done.")
	}
}

func buildNetwork(n int, seed int64, alpha int, logHandler slog.Handler) (*kademlia.SimulatedHub, []*kademlia.Kademlia) {
	// Temporarily discard logs during join/bootstrap so log file contains only measured lookups
	slog.SetDefault(slog.New(slog.DiscardHandler))

	hub := kademlia.NewSimulatedHub(seed)
	nodes := make([]*kademlia.Kademlia, n)
	rng := rand.New(rand.NewSource(seed))

	for i := range n {
		addr := fmt.Sprintf("10.%d.%d.%d:%d",
			rng.Intn(250)+1, rng.Intn(250)+1, rng.Intn(250)+1, rng.Intn(50000)+1024)
		id := kademlia.NewKademliaIDFromAddress(addr)
		c := kademlia.NewContact(id, addr)
		rt := kademlia.NewRoutingTable(c)
		ds := kademlia.NewDataStore()
		net := kademlia.NewSimulatedNetwork(c, rt, hub, ds)
		nodes[i] = kademlia.NewKademlia(c, net, rt, ds, alpha)
	}

	for i := 1; i < n; i++ {
		_ = nodes[i].Join(nodes[0].Me)
	}

	slog.SetDefault(slog.New(logHandler))
	return hub, nodes
}

func randomID(rng *rand.Rand) *kademlia.KademliaID {
	var id kademlia.KademliaID
	for i := 0; i < kademlia.IDLength; i++ {
		id[i] = byte(rng.Intn(256))
	}
	return &id
}

func parseInts(s string) ([]int, error) {
	var res []int
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			v, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			res = append(res, v)
		}
	}
	return res, nil
}

func parseInt64s(s string) ([]int64, error) {
	var res []int64
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			v, err := strconv.ParseInt(p, 10, 64)
			if err != nil {
				return nil, err
			}
			res = append(res, v)
		}
	}
	return res, nil
}

func parseFloats(s string) ([]float64, error) {
	var res []float64
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			v, err := strconv.ParseFloat(p, 64)
			if err != nil {
				return nil, err
			}
			res = append(res, v)
		}
	}
	return res, nil
}
