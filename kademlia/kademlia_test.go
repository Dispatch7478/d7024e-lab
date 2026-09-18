package kademlia

import (
	"fmt"
	"testing"
)

// Helper to create and start a test Kademlia node using SimulatedNetwork
func setupTestNode(t *testing.T, idStr string, alpha int, hub ...*SimulatedHub) (*Kademlia, func()) {
	t.Helper()

	var h *SimulatedHub
	if len(hub) > 0 && hub[0] != nil {
		h = hub[0]
	} else {
		h = NewSimulatedHub()
	}

	var id *KademliaID
	if idStr != "" {
		id = NewKademliaID(idStr)
	} else {
		id = NewRandomKademliaID()
	}

	addr := fmt.Sprintf("sim:%s", id.String()[:12])
	me := NewContact(id, addr)
	rt := NewRoutingTable(me)
	network := NewSimulatedNetwork(me, rt, h)

	kad := NewKademlia(me, network, rt, alpha)

	cleanup := func() {
		network.Close()
	}

	return kad, cleanup
}

func TestNewKademlia(t *testing.T) {
	addr := "127.0.0.1:8050"
	id := NewKademliaIDFromAddress(addr)
	me := NewContact(id, addr)
	rt := NewRoutingTable(me)
	net := NewUDPNetwork(me, rt)

	t.Run("Default alpha when passing 0", func(t *testing.T) {
		kadDefault := NewKademlia(me, net, rt, 0)
		if kadDefault.alpha != defaultAlpha {
			t.Errorf("expected default alpha %d, got %d", defaultAlpha, kadDefault.alpha)
		}
	})

	t.Run("Custom alpha", func(t *testing.T) {
		kadCustom := NewKademlia(me, net, rt, 5)
		if kadCustom.alpha != 5 {
			t.Errorf("expected custom alpha 5, got %d", kadCustom.alpha)
		}
	})
}

func TestKademlia_LookupContact(t *testing.T) {
	t.Run("Nil target contact returns empty slice", func(t *testing.T) {
		addr := "127.0.0.1:8051"
		id := NewKademliaIDFromAddress(addr)
		me := NewContact(id, addr)
		rt := NewRoutingTable(me)
		kad := NewKademlia(me, nil, rt, 0)

		resNil := kad.LookupContact(nil)
		if len(resNil) != 0 {
			t.Errorf("expected empty slice for nil target, got %v", resNil)
		}
	})

	t.Run("Nil target ID returns empty slice", func(t *testing.T) {
		addr := "127.0.0.1:8051"
		id := NewKademliaIDFromAddress(addr)
		me := NewContact(id, addr)
		rt := NewRoutingTable(me)
		kad := NewKademlia(me, nil, rt, 0)

		resNilID := kad.LookupContactByID(nil)
		if len(resNilID) != 0 {
			t.Errorf("expected empty slice for nil target ID, got %v", resNilID)
		}
	})

	t.Run("Nil routing table returns empty slice", func(t *testing.T) {
		addr := "127.0.0.1:8051"
		id := NewKademliaIDFromAddress(addr)
		me := NewContact(id, addr)
		kadNilRT := NewKademlia(me, nil, nil, 0)

		targetContact := NewContact(id, "")
		resNilRT := kadNilRT.LookupContact(&targetContact)
		if len(resNilRT) != 0 {
			t.Errorf("expected empty slice for nil routing table, got %v", resNilRT)
		}
	})

	t.Run("Nil network falls back to local routing table contacts", func(t *testing.T) {
		addr := "127.0.0.1:8051"
		id := NewKademliaIDFromAddress(addr)
		me := NewContact(id, addr)
		rt := NewRoutingTable(me)
		kad := NewKademlia(me, nil, rt, 0)

		c1 := NewContact(NewKademliaID("1000000000000000000000000000000000000000000000000000000000000000"), "127.0.0.1:8052")
		rt.AddContact(c1)

		targetContact := NewContact(id, "")
		resLocal := kad.LookupContact(&targetContact)
		if len(resLocal) != 1 || !resLocal[0].ID.Equals(c1.ID) {
			t.Errorf("expected local routing table contact c1, got %v", resLocal)
		}
	})

	t.Run("Single hop lookup discovers indirect contact", func(t *testing.T) {
		hub := NewSimulatedHub()
		kadA, cleanupA := setupTestNode(t, "1000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupA()

		kadB, cleanupB := setupTestNode(t, "2000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupB()

		// Node C is known to Node B
		kadC, cleanupC := setupTestNode(t, "3000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupC()
		c3ID := kadC.Me.ID
		kadB.RoutingTable.AddContact(kadC.Me)

		// Node A only knows Node B initially
		kadA.RoutingTable.AddContact(kadB.Me)

		// Node A looks up target 3000... (closest to Node C)
		target := c3ID
		targetContact := NewContact(target, "")
		closest := kadA.LookupContact(&targetContact)

		// Node A should have queried B, received C, queried C, and returned both
		foundC := false
		foundB := false
		for _, c := range closest {
			if c.ID.Equals(c3ID) {
				foundC = true
			}
			if c.ID.Equals(kadB.Me.ID) {
				foundB = true
			}
		}

		if !foundB {
			t.Errorf("expected Node B in lookup results")
		}
		if !foundC {
			t.Errorf("expected Node C to be discovered and returned in lookup results")
		}

		// Verify Node C was also added to Node A's local routing table
		rtClosest := kadA.RoutingTable.FindClosestContacts(target, bucketSize)
		rtHasC := false
		for _, c := range rtClosest {
			if c.ID.Equals(c3ID) {
				rtHasC = true
			}
		}
		if !rtHasC {
			t.Errorf("expected Node C to be populated into Node A's routing table")
		}
	})

	t.Run("Multi-hop network iterative lookup discovers target across chain", func(t *testing.T) {
		// Chain network: Node A -> Node B -> Node C -> Node D
		hub := NewSimulatedHub()
		kadA, cleanupA := setupTestNode(t, "1000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupA()
		kadB, cleanupB := setupTestNode(t, "2000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupB()
		kadC, cleanupC := setupTestNode(t, "3000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupC()
		kadD, cleanupD := setupTestNode(t, "4000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupD()

		kadA.RoutingTable.AddContact(kadB.Me)
		kadB.RoutingTable.AddContact(kadC.Me)
		kadC.RoutingTable.AddContact(kadD.Me)

		// Node A looks up Node D's ID
		target := kadD.Me.ID
		targetContact := NewContact(target, "")
		results := kadA.LookupContact(&targetContact)

		// Node A should iteratively query B -> learns C -> queries C -> learns D -> queries D
		foundD := false
		for _, c := range results {
			if c.ID.Equals(target) {
				foundD = true
			}
		}
		if !foundD {
			t.Fatalf("expected Node D to be discovered via multi-hop lookup, got %v", results)
		}

		// Check that closest contacts are sorted by distance to target
		for i := 0; i < len(results)-1; i++ {
			if !results[i].Less(&results[i+1]) && !results[i].distance.Equals(results[i+1].distance) {
				t.Errorf("expected results to be sorted by distance, but index %d is not less than %d", i, i+1)
			}
		}
	})

	t.Run("Unresponsive node is excluded from results", func(t *testing.T) {
		hub := NewSimulatedHub()
		kadA, cleanupA := setupTestNode(t, "1000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupA()

		kadB, cleanupB := setupTestNode(t, "2000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupB()

		// Dead node pointing to an unreachable address not in the hub
		deadID := NewKademliaID("3000000000000000000000000000000000000000000000000000000000000000")
		deadContact := NewContact(deadID, "sim:dead_unreachable_node")

		kadA.RoutingTable.AddContact(kadB.Me)
		kadA.RoutingTable.AddContact(deadContact)

		target := NewKademliaID("2000000000000000000000000000000000000000000000000000000000000000")
		results := kadA.LookupContactByID(target)

		// Dead node should NOT be in the final queried results
		for _, c := range results {
			if c.ID.Equals(deadID) {
				t.Errorf("unresponsive contact %v should not be returned in lookup results", deadID)
			}
		}

		// Responsive node B should be present
		foundB := false
		for _, c := range results {
			if c.ID.Equals(kadB.Me.ID) {
				foundB = true
			}
		}
		if !foundB {
			t.Errorf("expected responsive node B in results")
		}
	})

	t.Run("Parallel probes with alpha=3", func(t *testing.T) {
		hub := NewSimulatedHub()
		kadA, cleanupA := setupTestNode(t, "0000000000000000000000000000000000000000000000000000000000000001", 3, hub)
		defer cleanupA()

		var cleanups []func()
		for i := 2; i <= 6; i++ {
			idStr := fmt.Sprintf("%064x", i)
			node, cleanup := setupTestNode(t, idStr, 3, hub)
			cleanups = append(cleanups, cleanup)
			kadA.RoutingTable.AddContact(node.Me)
		}
		defer func() {
			for _, c := range cleanups {
				c()
			}
		}()

		target := NewKademliaID(fmt.Sprintf("%064x", 3))
		res := kadA.LookupContactByID(target)
		if len(res) == 0 {
			t.Errorf("expected non-empty lookup results")
		}
	})
}

func TestKademlia_Join(t *testing.T) {
	hub := NewSimulatedHub()
	kadA, cleanupA := setupTestNode(t, "1000000000000000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupA()

	kadB, cleanupB := setupTestNode(t, "2000000000000000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupB()

	t.Run("Nil bootstrap contact ID returns error", func(t *testing.T) {
		nilContact := Contact{ID: nil}
		if err := kadA.Join(nilContact); err == nil {
			t.Errorf("expected error joining with nil ID bootstrap")
		}
	})

	t.Run("Self as bootstrap node returns error", func(t *testing.T) {
		if err := kadA.Join(kadA.Me); err == nil {
			t.Errorf("expected error joining with self as bootstrap")
		}
	})

	t.Run("Nil routing table returns error", func(t *testing.T) {
		kadNilRT := NewKademlia(kadA.Me, kadA.Network, nil, 0)
		if err := kadNilRT.Join(kadB.Me); err == nil {
			t.Errorf("expected error joining with nil routing table")
		}
	})

	t.Run("Successful join adds bootstrap and performs self lookup", func(t *testing.T) {
		if err := kadA.Join(kadB.Me); err != nil {
			t.Fatalf("expected successful join, got: %v", err)
		}

		// Node A should now have Node B in its routing table
		closest := kadA.RoutingTable.FindClosestContacts(kadB.Me.ID, bucketSize)
		foundB := false
		for _, c := range closest {
			if c.ID.Equals(kadB.Me.ID) {
				foundB = true
			}
		}
		if !foundB {
			t.Errorf("expected Node B in Node A's routing table after join")
		}
	})

	// Need to test refresh later.
}
