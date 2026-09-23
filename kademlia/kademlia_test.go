package kademlia

import (
	"errors"
	"fmt"
	"testing"
	"time"
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
	ds := NewDataStore()
	network := NewSimulatedNetwork(me, rt, h, ds)

	kad := NewKademlia(me, network, rt, ds, alpha)

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
	ds := NewDataStore()
	net := NewUDPNetwork(me, rt, ds)

	t.Run("Default alpha when passing 0", func(t *testing.T) {
		kadDefault := NewKademlia(me, net, rt, ds, 0)
		if kadDefault.alpha != defaultAlpha {
			t.Errorf("expected default alpha %d, got %d", defaultAlpha, kadDefault.alpha)
		}
	})

	t.Run("Custom alpha", func(t *testing.T) {
		kadCustom := NewKademlia(me, net, rt, ds, 5)
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
		kad := NewKademlia(me, nil, rt, NewDataStore(), 0)

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
		kad := NewKademlia(me, nil, rt, NewDataStore(), 0)

		resNilID := kad.LookupContactByID(nil)
		if len(resNilID) != 0 {
			t.Errorf("expected empty slice for nil target ID, got %v", resNilID)
		}
	})

	t.Run("Nil routing table returns empty slice", func(t *testing.T) {
		addr := "127.0.0.1:8051"
		id := NewKademliaIDFromAddress(addr)
		me := NewContact(id, addr)
		kadNilRT := NewKademlia(me, nil, nil, NewDataStore(), 0)

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
		kad := NewKademlia(me, nil, rt, NewDataStore(), 0)

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
		kadNilRT := NewKademlia(kadA.Me, kadA.Network, nil, kadA.DataStore, 0)
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

	t.Run("generateRandomIDForBucket produces IDs in correct bucket", func(t *testing.T) {
		for bucket := 0; bucket < 256; bucket++ {
			randID := kadA.generateRandomIDForBucket(bucket)
			gotBucket := kadA.RoutingTable.getBucketIndex(randID)
			if gotBucket != bucket {
				t.Errorf("for bucket %d, generated ID landed in bucket %d", bucket, gotBucket)
			}
		}
	})
}

func TestKademlia_StoreAndLookupData(t *testing.T) {
	hub := NewSimulatedHub()

	kadA, cleanupA := setupTestNode(t, "1000000000000000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupA()

	kadB, cleanupB := setupTestNode(t, "2000000000000000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupB()

	kadC, cleanupC := setupTestNode(t, "3000000000000000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupC()

	// Connect nodes in routing tables
	kadA.RoutingTable.AddContact(kadB.Me)
	kadB.RoutingTable.AddContact(kadA.Me)
	kadB.RoutingTable.AddContact(kadC.Me)
	kadC.RoutingTable.AddContact(kadB.Me)

	t.Run("Empty data returns error", func(t *testing.T) {
		_, err := kadA.Store([]byte{})
		if err == nil {
			t.Errorf("expected error storing empty data")
		}
	})

	t.Run("Nil target ID returns error", func(t *testing.T) {
		_, _, err := kadA.LookupDataByID(nil)
		if err == nil {
			t.Errorf("expected error looking up nil target ID")
		}
	})

	t.Run("Missing key returns ErrValueNotFound", func(t *testing.T) {
		missingKey := NewKademliaID("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		_, _, err := kadA.LookupDataByID(missingKey)
		if !errors.Is(err, ErrValueNotFound) {
			t.Errorf("expected ErrValueNotFound, got %v", err)
		}
	})

	t.Run("Store and LookupData across network", func(t *testing.T) {
		data := []byte("distributed package version 1.0.0 binary content")
		key, err := kadA.Store(data)
		if err != nil {
			t.Fatalf("expected Store to succeed, got: %v", err)
		}

		// Node A should have it stored locally
		if !kadA.DataStore.Has(*key) {
			t.Errorf("expected Node A to store data locally")
		}

		// Node B should also have it stored (closest node)
		if !kadB.DataStore.Has(*key) {
			t.Errorf("expected Node B to have received STORE RPC")
		}

		// Node C does not have it locally
		if kadC.DataStore.Has(*key) {
			kadC.DataStore.Delete(*key)
		}

		// Node C performs iterative LookupData(key.String())
		retrieved, responder, err := kadC.LookupData(key.String())
		if err != nil {
			t.Fatalf("expected LookupData to succeed, got: %v", err)
		}

		if string(retrieved) != string(data) {
			t.Errorf("expected retrieved data %s, got %s", string(data), string(retrieved))
		}

		if responder == nil {
			t.Errorf("expected responder contact to be returned")
		}

		// Node C should have cached the value locally in its DataStore
		if !kadC.DataStore.Has(*key) {
			t.Errorf("expected Node C to cache the looked up value locally")
		}
	})

	t.Run("Replicate republishes stored values", func(t *testing.T) {
		kadD, cleanupD := setupTestNode(t, "4000000000000000000000000000000000000000000000000000000000000000", 3, hub)
		defer cleanupD()

		kadB.RoutingTable.AddContact(kadD.Me)
		kadD.RoutingTable.AddContact(kadB.Me)

		val := []byte("replicated package blob")
		key := NewKademliaIDFromData(val)

		// Directly put in Node B's local datastore without network store
		_ = kadB.DataStore.Store(*key, val)

		// Node D does not have it
		if kadD.DataStore.Has(*key) {
			kadD.DataStore.Delete(*key)
		}

		// Node B triggers Replicate()
		kadB.Replicate()

		// Give async goroutine a brief moment to dispatch
		time.Sleep(20 * time.Millisecond)

		// Verify Node D now has the replicated data
		if !kadD.DataStore.Has(*key) {
			t.Errorf("expected Node D to receive replicated key")
		}
	})

	t.Run("Corrupted data with hash mismatch is discarded by client", func(t *testing.T) {
		validData := []byte("legit data")
		key := NewKademliaIDFromData(validData)

		// Tampered node B has corrupted data stored under key
		corruptedDS := NewDataStore()
		corruptedDS.StoreUnchecked(*key, []byte("tampered evil content"))
		kadB.DataStore = corruptedDS
		if netB, ok := kadB.Network.(*SimulatedNetwork); ok {
			netB.ds = corruptedDS
		}

		// Node C does not have the data
		kadC.DataStore.Delete(*key)

		// Node C queries for key -> receives corrupted data from B -> must discard it and fail with ErrValueNotFound
		res, _, err := kadC.LookupData(key.String())
		if res != nil {
			t.Errorf("expected client to discard corrupted data, but got %s", string(res))
		}
		if !errors.Is(err, ErrValueNotFound) {
			t.Errorf("expected ErrValueNotFound after discarding corrupted data, got %v", err)
		}
	})
}

func TestKademlia_ReplicationWorker(t *testing.T) {
	hub := NewSimulatedHub()
	defer hub.ResetMetrics()

	idA := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001")
	idB := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002")

	contactA := NewContact(idA, "10.0.0.1:8000")
	contactB := NewContact(idB, "10.0.0.2:8000")

	rtA := NewRoutingTable(contactA)
	rtB := NewRoutingTable(contactB)

	dsA := NewDataStore()
	dsB := NewDataStore()

	netA := NewSimulatedNetwork(contactA, rtA, hub, dsA)
	netB := NewSimulatedNetwork(contactB, rtB, hub, dsB)
	defer netA.Close()
	defer netB.Close()

	kadA := NewKademlia(contactA, netA, rtA, dsA, 3)
	kadB := NewKademlia(contactB, netB, rtB, dsB, 3)

	rtA.AddContact(contactB)
	rtB.AddContact(contactA)

	t.Run("Replication worker replicates periodically", func(t *testing.T) {
		val := []byte("periodic replication test payload")
		key := NewKademliaIDFromData(val)

		// Store only in Node A
		_ = kadA.DataStore.Store(*key, val)

		// Verify Node B does not have it initially
		if kadB.DataStore.Has(*key) {
			kadB.DataStore.Delete(*key)
		}

		// Start worker on Node A with a fast 25ms interval
		kadA.StartReplicationWorker(25 * time.Millisecond)
		defer kadA.StopReplicationWorker()

		// Poll until Node B receives the data via worker replication
		replicated := false
		for i := 0; i < 20; i++ {
			time.Sleep(10 * time.Millisecond)
			if kadB.DataStore.Has(*key) {
				replicated = true
				break
			}
		}

		if !replicated {
			t.Errorf("expected replication worker to replicate key to peer within deadline")
		}
	})

	t.Run("StopReplicationWorker is clean and idempotent", func(t *testing.T) {
		kad := NewKademlia(contactA, netA, rtA, dsA, 3)
		// Stopping when not started should not panic
		kad.StopReplicationWorker()

		kad.StartReplicationWorker(20 * time.Millisecond)
		kad.StopReplicationWorker()
		// Calling stop a second time should not panic
		kad.StopReplicationWorker()
	})

	t.Run("StartReplicationWorker handles default interval and restarts", func(t *testing.T) {
		kad := NewKademlia(contactA, netA, rtA, dsA, 3)
		kad.StartReplicationWorker(0)
		if kad.replicationInterval != DefaultReplicationInterval {
			t.Errorf("expected default interval %v, got %v", DefaultReplicationInterval, kad.replicationInterval)
		}
		// Restart with different interval
		kad.StartReplicationWorker(50 * time.Millisecond)
		if kad.replicationInterval != 50*time.Millisecond {
			t.Errorf("expected updated interval 50ms, got %v", kad.replicationInterval)
		}
		kad.StopReplicationWorker()
	})
}
