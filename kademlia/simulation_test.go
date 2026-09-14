package kademlia

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestSimulation_1000Nodes(t *testing.T) {
	// Seeded for reproducibility
	hub := NewSimulatedHub(12345)

	const totalNodes = 1000

	nodes := make([]*Kademlia, totalNodes)

	// Create bootstrap node (Node 0)
	bootstrapID := NewKademliaID(fmt.Sprintf("%064x", 1))
	bootstrapContact := NewContact(bootstrapID, "sim:node0")
	bootstrapRT := NewRoutingTable(bootstrapContact)
	bootstrapNet := NewSimulatedNetwork(bootstrapContact, bootstrapRT, hub)
	nodes[0] = NewKademlia(bootstrapContact, bootstrapNet, bootstrapRT, 3)

	// Create remaining 999 nodes
	for i := 1; i < totalNodes; i++ {
		addr := fmt.Sprintf("sim:node%d", i)
		id := NewKademliaIDFromAddress(addr)
		contact := NewContact(id, addr)
		rt := NewRoutingTable(contact)
		net := NewSimulatedNetwork(contact, rt, hub)
		nodes[i] = NewKademlia(contact, net, rt, 3)
	}

	t.Run("Bootstrap 1000 nodes into the network", func(t *testing.T) {
		start := time.Now()

		// Join nodes into the network
		// Nodes join via the bootstrap node (or an already joined node)
		for i := 1; i < totalNodes; i++ {
			// Connect to bootstrap node
			err := nodes[i].Join(nodes[0].me)
			if err != nil {
				t.Fatalf("failed to join node %d: %v", i, err)
			}
		}

		elapsed := time.Since(start)
		t.Logf("1000 nodes joined network in %v (total probes dispatched: %d)", elapsed, hub.TotalProbes())
	})

	t.Run("Lookup target in 1000-node network", func(t *testing.T) {
		hub.ResetMetrics()

		// Random node looks up random target
		rng := rand.New(rand.NewSource(999))
		const lookupSamples = 20
		totalHops := int64(0)

		for range lookupSamples {
			nodeIdx := rng.Intn(totalNodes)
			target := NewRandomKademliaID()

			beforeProbes := hub.TotalProbes()
			results := nodes[nodeIdx].LookupContactByID(target)
			afterProbes := hub.TotalProbes()

			probesUsed := afterProbes - beforeProbes
			totalHops += probesUsed

			if len(results) == 0 {
				t.Errorf("lookup from node %d for target %v returned 0 results", nodeIdx, target)
			}

			// Verify results are sorted by distance
			for i := 0; i < len(results)-1; i++ {
				if results[i+1].Less(&results[i]) {
					t.Errorf("results are not properly ordered by distance")
				}
			}
		}

		avgProbes := float64(totalHops) / float64(lookupSamples)
		t.Logf("Average probes per lookup across 1000 nodes: %.2f", avgProbes)
	})

	t.Run("Lookup resilience under 10% packet loss", func(t *testing.T) {
		hub.ResetMetrics()
		hub.SetPacketLoss(0.10) // 10% packet loss
		defer hub.SetPacketLoss(0.0)

		rng := rand.New(rand.NewSource(888))
		successCount := 0
		const testRuns = 15

		for i := 0; i < testRuns; i++ {
			nodeIdx := rng.Intn(totalNodes)
			target := NewRandomKademliaID()

			results := nodes[nodeIdx].LookupContactByID(target)
			if len(results) > 0 {
				successCount++
			}
		}

		successRate := float64(successCount) / float64(testRuns) * 100
		t.Logf("Lookup success rate with 10%% packet loss: %.1f%% (%d/%d successful, probes: total=%d, dropped=%d)",
			successRate, successCount, testRuns, hub.TotalProbes(), hub.DroppedProbes())

		if successRate < 80.0 {
			t.Errorf("expected success rate >= 80%% with 10%% packet loss, got %.1f%%", successRate)
		}
	})
}
