package kademlia

import (
	"d7024e/registry"
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
			gotBucket := kadA.RoutingTable.GetBucketIndex(randID)
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

func TestKademlia_StoreWithKeyAndLatestPointer(t *testing.T) {
	hub := NewSimulatedHub()
	kadA, cleanupA := setupTestNode(t, "1000000000010000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupA()
	kadB, cleanupB := setupTestNode(t, "1000000000020000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupB()

	kadA.RoutingTable.AddContact(kadB.Me)
	kadB.RoutingTable.AddContact(kadA.Me)

	domain := "example.com"
	pkg := "net-pkg"
	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	kadA.SetDNSResolver(resolver)
	kadB.SetDNSResolver(resolver)

	// Create v1.0.0
	_, _, vr1Bytes, vr1Hash, lp1, _, lpKey := createTestRelease(t, dkp, pkg, "1.0.0", "blob 1", registry.ZeroHash)

	// Store VR1 on Node A
	_, err := kadA.Store(vr1Bytes)
	if err != nil {
		t.Fatalf("failed to store vr1: %v", err)
	}

	// Store LatestPointer using StoreLatestPointer helper
	err = kadA.StoreLatestPointer(lp1)
	if err != nil {
		t.Fatalf("failed to store latest pointer: %v", err)
	}

	// Verify both nodes have the latest pointer
	if !kadA.DataStore.Has(lpKey) {
		t.Errorf("expected kadA to have latest pointer locally")
	}
	if !kadB.DataStore.Has(lpKey) {
		t.Errorf("expected kadB to have received latest pointer via network store")
	}

	// Lookup from KadB using LookupLatestPointer
	retrievedLP, _, err := kadB.LookupLatestPointer(domain, pkg)
	if err != nil {
		t.Fatalf("LookupLatestPointer failed: %v", err)
	}
	if retrievedLP.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", retrievedLP.Version)
	}

	// Error handling: nil pointer
	if err := kadA.StoreLatestPointer(nil); err == nil {
		t.Errorf("expected error for nil LatestPointer")
	}
	// Error handling: nil key in StoreWithKey
	if err := kadA.StoreWithKey(nil, []byte("data")); err == nil {
		t.Errorf("expected error for nil key in StoreWithKey")
	}
	// Error handling: empty data in StoreWithKey
	if err := kadA.StoreWithKey(&lpKey, []byte{}); err == nil {
		t.Errorf("expected error for empty data in StoreWithKey")
	}

	_ = vr1Hash
}

func TestKademlia_NetworkCatchUp(t *testing.T) {
	hub := NewSimulatedHub()
	kadA, cleanupA := setupTestNode(t, "2000000000010000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupA()
	kadB, cleanupB := setupTestNode(t, "2000000000020000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupB()

	kadA.RoutingTable.AddContact(kadB.Me)
	kadB.RoutingTable.AddContact(kadA.Me)

	domain := "example.com"
	pkg := "catchup-net"
	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)

	kadA.SetDNSResolver(resolver)
	kadB.SetDNSResolver(resolver)

	// Node A prepares releases v1.0.0 and v2.0.0
	_, _, vr1Bytes, vr1Hash, _, _, _ := createTestRelease(t, dkp, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, lp2, _, lpKey := createTestRelease(t, dkp, pkg, "2.0.0", "b2", vr1Hash)

	vr1Key := *NewKademliaID(vr1Hash)
	vr2Key := *NewKademliaID(vr2Hash)

	// Only Node A stores VR1 and VR2 in its DataStore (simulating it was uploaded to Node A)
	_ = kadA.DataStore.Store(vr1Key, vr1Bytes)
	_ = kadA.DataStore.Store(vr2Key, vr2Bytes)
	if kadB.DataStore.Has(vr1Key) || kadB.DataStore.Has(vr2Key) {
		t.Fatalf("kadB should not have VR1 or VR2 initially")
	}

	// Now Node B is asked to store LatestPointer v2.0.0 directly
	// Node B's DataStore will detect it lacks VR2 and VR1,
	// and will use its default recordFetcher (calling kadB.LookupData)
	// to query Node A across the network and retrieve them.
	err := kadB.StoreLatestPointer(lp2)
	if err != nil {
		t.Fatalf("expected Node B to catch up across network and store LP: %v", err)
	}

	// Verify Node B caught up: it now has VR1, VR2, and the LatestPointer locally.
	if !kadB.DataStore.Has(vr1Key) {
		t.Errorf("expected kadB to have caught up and stored vr1 locally")
	}
	if !kadB.DataStore.Has(vr2Key) {
		t.Errorf("expected kadB to have caught up and stored vr2 locally")
	}
	if !kadB.DataStore.Has(lpKey) {
		t.Errorf("expected kadB to have stored latest pointer locally")
	}
}

func TestKademlia_PeerRejection(t *testing.T) {
	hub := NewSimulatedHub()
	kadA, cleanupA := setupTestNode(t, "3000000000010000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupA()
	kadB, cleanupB := setupTestNode(t, "3000000000020000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupB()

	kadA.RoutingTable.AddContact(kadB.Me)
	kadB.RoutingTable.AddContact(kadA.Me)

	domain := "example.com"
	pkg := "peer-reject"
	dkpOwner, _ := registry.GenerateDomainKeyPair(domain)
	dkpAttacker, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkpOwner.PublicKey)

	kadA.SetDNSResolver(resolver)
	kadB.SetDNSResolver(resolver)

	// Legitimate release v1.0.0 and v2.0.0
	_, _, vr1Bytes, vr1Hash, lp1, _, lpKey := createTestRelease(t, dkpOwner, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, lp2, _, _ := createTestRelease(t, dkpOwner, pkg, "2.0.0", "b2", vr1Hash)

	_, _ = kadA.Store(vr1Bytes)
	_, _ = kadA.Store(vr2Bytes)
	_, _ = kadB.Store(vr1Bytes)
	_, _ = kadB.Store(vr2Bytes)

	// Store v2.0.0 on both nodes
	_ = kadA.StoreLatestPointer(lp2)

	// Case 1: Attacker tries to publish rollback (v1.0.0) from KadA
	err := kadA.StoreLatestPointer(lp1)
	if !errors.Is(err, ErrVersionRollback) {
		t.Errorf("expected ErrVersionRollback when attempting rollback store: %v", err)
	}

	// Case 2: Attacker tries to publish forged pointer signed with attacker key
	_, _, vr3Bytes, vr3Hash, lp3Forged, _, _ := createTestRelease(t, dkpAttacker, pkg, "3.0.0", "b3", vr2Hash)
	_, _ = kadA.Store(vr3Bytes)
	_ = vr3Hash
	err = kadA.StoreLatestPointer(lp3Forged)
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for forged pointer: %v", err)
	}

	// Case 3: Attacker tries to publish fork (v3.0.0 pointing to alt root)
	_, _, vrAltBytes, vrAltHash, _, _, _ := createTestRelease(t, dkpOwner, pkg, "1.0.0", "alt root", registry.ZeroHash)
	_, _, vrForkBytes, vrForkHash, lpFork, _, _ := createTestRelease(t, dkpOwner, pkg, "3.0.0", "fork", vrAltHash)
	_, _ = kadA.Store(vrAltBytes)
	_, _ = kadA.Store(vrForkBytes)
	_ = vrForkHash
	err = kadA.StoreLatestPointer(lpFork)
	if !errors.Is(err, ErrHistoryFork) {
		t.Errorf("expected ErrHistoryFork for branching history: %v", err)
	}

	_ = lpKey
}

func TestKademlia_RemotePeerNetworkRejection(t *testing.T) {
	hub := NewSimulatedHub()
	kadVictim, cleanupVictim := setupTestNode(t, "4000000000010000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupVictim()
	kadAttacker, cleanupAttacker := setupTestNode(t, "4000000000020000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupAttacker()

	kadVictim.RoutingTable.AddContact(kadAttacker.Me)
	kadAttacker.RoutingTable.AddContact(kadVictim.Me)

	domain := "example.com"
	pkg := "net-peer-reject"
	dkpOwner, _ := registry.GenerateDomainKeyPair(domain)
	dkpAttacker, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkpOwner.PublicKey)

	kadVictim.SetDNSResolver(resolver)
	kadAttacker.SetDNSResolver(resolver)

	// Legitimate releases v1.0.0 and v2.0.0
	_, _, vr1Bytes, vr1Hash, lp1, lp1Bytes, lpKey := createTestRelease(t, dkpOwner, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, lp2, _, _ := createTestRelease(t, dkpOwner, pkg, "2.0.0", "b2", vr1Hash)

	_, _ = kadVictim.Store(vr1Bytes)
	_, _ = kadVictim.Store(vr2Bytes)
	_ = kadVictim.StoreLatestPointer(lp2) // Victim is at v2.0.0

	// Attacker sends rollback (v1.0.0) STORE RPC directly over network to victim
	errRollback := kadAttacker.Network.SendStoreMessage(&kadVictim.Me, &lpKey, lp1Bytes)
	if !errors.Is(errRollback, ErrVersionRollback) {
		t.Errorf("expected victim to reject rollback RPC with ErrVersionRollback, got: %v", errRollback)
	}

	// Attacker sends forged signature STORE RPC directly over network to victim
	_, _, vr3Bytes, vr3Hash, lpForged, lpForgedBytes, _ := createTestRelease(t, dkpAttacker, pkg, "3.0.0", "b3", vr2Hash)
	_, _ = kadVictim.Store(vr3Bytes)
	_ = vr3Hash
	errForged := kadAttacker.Network.SendStoreMessage(&kadVictim.Me, &lpKey, lpForgedBytes)
	if !errors.Is(errForged, ErrUnauthorized) {
		t.Errorf("expected victim to reject forged RPC with ErrUnauthorized, got: %v", errForged)
	}

	// Attacker sends fork STORE RPC directly over network to victim
	_, _, vrAltBytes, vrAltHash, _, _, _ := createTestRelease(t, dkpOwner, pkg, "1.0.0", "alt root", registry.ZeroHash)
	_, _, vrForkBytes, vrForkHash, lpFork, lpForkBytes, _ := createTestRelease(t, dkpOwner, pkg, "3.0.0", "fork", vrAltHash)
	_, _ = kadVictim.Store(vrAltBytes)
	_, _ = kadVictim.Store(vrForkBytes)
	_ = vrForkHash
	errFork := kadAttacker.Network.SendStoreMessage(&kadVictim.Me, &lpKey, lpForkBytes)
	if !errors.Is(errFork, ErrHistoryFork) {
		t.Errorf("expected victim to reject fork RPC with ErrHistoryFork, got: %v", errFork)
	}

	// Verify victim's DataStore still holds legitimate v2.0.0 pointer after all malicious attacks!
	val, found := kadVictim.DataStore.Get(lpKey)
	if !found {
		t.Fatalf("expected victim to retain latest pointer")
	}
	lpCurrent, err := registry.ParseLatestPointer(val)
	if err != nil {
		t.Fatalf("failed to parse victim latest pointer: %v", err)
	}
	if lpCurrent.Version != "2.0.0" {
		t.Errorf("expected victim to remain at v2.0.0, got %s", lpCurrent.Version)
	}

	_ = lp1
	_ = lpForged
	_ = lpFork
}

func TestKademlia_DNSResolverGetter(t *testing.T) {
	hub := NewSimulatedHub()
	kad, cleanup := setupTestNode(t, "5000000000010000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanup()

	if kad.DNSResolver() != nil {
		t.Errorf("expected initial nil DNSResolver")
	}

	resolver := registry.NewMockDNSResolver()
	kad.SetDNSResolver(resolver)

	if kad.DNSResolver() != resolver {
		t.Errorf("DNSResolver getter returned mismatch")
	}

	// Nil datastore case
	kadNilDS := &Kademlia{}
	if kadNilDS.DNSResolver() != nil {
		t.Errorf("expected nil for Kademlia with nil DataStore")
	}
	kadNilDS.SetDNSResolver(resolver) // Should not panic
}

func TestKademlia_StoreLatestPointerForce_And_WalkVersionChain(t *testing.T) {
	hub := NewSimulatedHub()
	kadA, cleanupA := setupTestNode(t, "6000000000010000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupA()
	kadB, cleanupB := setupTestNode(t, "6000000000020000000000000000000000000000000000000000000000000000", 3, hub)
	defer cleanupB()

	kadA.RoutingTable.AddContact(kadB.Me)
	kadB.RoutingTable.AddContact(kadA.Me)

	domain := "example.com"
	pkg := "force-walk-pkg"
	dkp, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkp.PublicKey)
	kadA.SetDNSResolver(resolver)
	kadB.SetDNSResolver(resolver)

	// Publish v1.0.0 and v2.0.0 legitimately on KadA
	_, _, vr1Bytes, vr1Hash, _, _, _ := createTestRelease(t, dkp, pkg, "1.0.0", "blob1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, lp2, _, _ := createTestRelease(t, dkp, pkg, "2.0.0", "blob2", vr1Hash)

	_, _ = kadA.Store(vr1Bytes)
	_, _ = kadA.Store(vr2Bytes)
	err := kadA.StoreLatestPointer(lp2)
	if err != nil {
		t.Fatalf("StoreLatestPointer failed: %v", err)
	}

	// Test WalkVersionChain on KadA
	chain, err := kadA.WalkVersionChain(vr2Hash)
	if err != nil {
		t.Fatalf("WalkVersionChain failed: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected 2 records in chain, got %d", len(chain))
	}
	if chain[0].Version != "2.0.0" || chain[1].Version != "1.0.0" {
		t.Errorf("unexpected chain order: %s, %s", chain[0].Version, chain[1].Version)
	}

	// Test StoreLatestPointerForce with rollback: KadA forces lp1 (v1.0.0) locally and across network
	_, _, _, _, lp1, _, _ := createTestRelease(t, dkp, pkg, "1.0.0", "blob1", registry.ZeroHash)
	errForce := kadA.StoreLatestPointerForce(lp1)
	if errForce != nil {
		t.Fatalf("StoreLatestPointerForce failed: %v", errForce)
	}

	// KadA's local DataStore accepted it via StoreUnchecked
	retrievedLP, _, err := kadA.LookupLatestPointer(domain, pkg)
	if err != nil || retrievedLP == nil {
		t.Fatalf("expected to find forced pointer on KadA: %v", err)
	}
	if retrievedLP.Version != "1.0.0" {
		t.Errorf("expected KadA to have forced v1.0.0, got %s", retrievedLP.Version)
	}

	// Edge cases: nil checks on StoreWithKeyForce and StoreLatestPointerForce
	if err := kadA.StoreWithKeyForce(nil, []byte("data")); err == nil {
		t.Errorf("expected error for nil key")
	}
	dummyKey := NewKademliaID("1234567890123456789012345678901234567890123456789012345678901234")
	if err := kadA.StoreWithKeyForce(dummyKey, nil); err == nil {
		t.Errorf("expected error for empty data")
	}
	if err := kadA.StoreLatestPointerForce(nil); err == nil {
		t.Errorf("expected error for nil pointer")
	}
}
