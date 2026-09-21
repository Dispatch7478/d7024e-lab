package kademlia

import (
	"testing"
	"time"
)

func TestSimulatedNetwork(t *testing.T) {
	hub := NewSimulatedHub(42) // Fixed seed for determinism

	idA := NewKademliaID("1000000000000000000000000000000000000000000000000000000000000000")
	contactA := NewContact(idA, "sim:nodeA")
	rtA := NewRoutingTable(contactA)
	dsA := NewDataStore()
	netA := NewSimulatedNetwork(contactA, rtA, hub, dsA)
	defer netA.Close()

	idB := NewKademliaID("2000000000000000000000000000000000000000000000000000000000000000")
	contactB := NewContact(idB, "sim:nodeB")
	rtB := NewRoutingTable(contactB)
	dsB := NewDataStore()
	netB := NewSimulatedNetwork(contactB, rtB, hub, dsB)
	defer netB.Close()

	t.Run("Ping success and metrics", func(t *testing.T) {
		hub.ResetMetrics()
		reply, err := netA.SendPingMessage(&contactB)
		if err != nil {
			t.Fatalf("expected ping success, got: %v", err)
		}
		if reply == nil || reply.Type != Pong {
			t.Fatalf("expected Pong reply, got: %v", reply)
		}
		if !reply.Sender.ID.Equals(idB) {
			t.Errorf("expected reply sender to be node B")
		}
		if hub.TotalProbes() != 1 || hub.SuccessfulProbes() != 1 || hub.DroppedProbes() != 0 {
			t.Errorf("unexpected probe metrics: total=%d, success=%d, dropped=%d",
				hub.TotalProbes(), hub.SuccessfulProbes(), hub.DroppedProbes())
		}
	})

	t.Run("Ping unreachable node", func(t *testing.T) {
		unreachable := NewContact(NewKademliaID("9999999999999999999999999999999999999999999999999999999999999999"), "sim:unreachable")
		_, err := netA.SendPingMessage(&unreachable)
		if err == nil {
			t.Errorf("expected error pinging unreachable node")
		}
	})

	t.Run("FindContact returns closest contacts and updates receiver RT", func(t *testing.T) {
		idC := NewKademliaID("3000000000000000000000000000000000000000000000000000000000000000")
		contactC := NewContact(idC, "sim:nodeC")
		rtB.AddContact(contactC)

		target := idC
		contacts, err := netA.SendFindContactMessage(target, &contactB)
		if err != nil {
			t.Fatalf("expected find contact success, got: %v", err)
		}
		if len(contacts) != 1 || !contacts[0].ID.Equals(idC) {
			t.Errorf("expected node B to return contact C, got: %v", contacts)
		}

		// Node B's routing table should now also have Node A (the sender)
		closestToA := rtB.FindClosestContacts(idA, bucketSize)
		foundA := false
		for _, c := range closestToA {
			if c.ID.Equals(idA) {
				foundA = true
			}
		}
		if !foundA {
			t.Errorf("expected node B's routing table to be updated with sender node A")
		}
	})

	t.Run("Packet loss drops RPCs", func(t *testing.T) {
		hub.ResetMetrics()
		hub.SetPacketLoss(1.0) // 100% loss
		defer hub.SetPacketLoss(0.0)

		_, err := netA.SendPingMessage(&contactB)
		if err == nil {
			t.Errorf("expected error under 100%% packet loss")
		}
		if hub.DroppedProbes() != 1 {
			t.Errorf("expected dropped probes count to be 1, got %d", hub.DroppedProbes())
		}
	})

	t.Run("Simulated latency delays RPC", func(t *testing.T) {
		hub.SetLatency(20 * time.Millisecond)
		defer hub.SetLatency(0)

		start := time.Now()
		_, err := netA.SendPingMessage(&contactB)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("expected ping success with latency, got: %v", err)
		}
		if elapsed < 15*time.Millisecond {
			t.Errorf("expected elapsed time to be at least 15ms, got %v", elapsed)
		}
	})

	t.Run("Store and FindData in SimulatedNetwork", func(t *testing.T) {
		val := []byte("stored binary package data")
		key := NewKademliaIDFromData(val)

		// Node A stores data on Node B
		if err := netA.SendStoreMessage(&contactB, key, val); err != nil {
			t.Fatalf("expected store message to succeed, got: %v", err)
		}

		// Verify Node B has it in its datastore
		if !dsB.Has(*key) {
			t.Fatalf("expected node B to have stored the key")
		}

		// Node A finds data on Node B -> should return the data
		foundData, closest, err := netA.SendFindDataMessage(key, &contactB)
		if err != nil {
			t.Fatalf("expected find data to succeed, got: %v", err)
		}
		if string(foundData) != string(val) {
			t.Errorf("expected found data %s, got %s", string(val), string(foundData))
		}
		if len(closest) != 0 {
			t.Errorf("expected 0 closest contacts when data is found, got %d", len(closest))
		}

		// Querying for missing key on Node B -> should return closest contacts
		missingKey := NewKademliaID("9999999999999999999999999999999999999999999999999999999999999999")
		missingData, missingClosest, err := netA.SendFindDataMessage(missingKey, &contactB)
		if err != nil {
			t.Fatalf("expected find data to succeed, got: %v", err)
		}
		if len(missingData) != 0 {
			t.Errorf("expected nil/empty data for missing key, got %s", string(missingData))
		}
		if len(missingClosest) == 0 {
			t.Errorf("expected non-empty contacts returned for missing key")
		}
	})
}
