package kademlia

import (
	"fmt"
	"testing"
)

// FIXME: This test doesn't actually test anything. There is only one assertion
// that is included as an example.

func TestRoutingTable(t *testing.T) {
	me := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000"), "localhost:6767")

	t.Run("Empty routing tbale", func(t *testing.T) {
		target := NewRandomKademliaID()

		rt := NewRoutingTable(me)

		contacts := rt.FindClosestContacts(target, 20) // k=20

		if len(contacts) != 0 {
			t.Errorf("expected 0 contacts, got %d", len(contacts))
		}
	})

	t.Run("Ask for more contacts than exist", func(t *testing.T) {
		c1 := NewContact(NewKademliaID("1000000000000000000000000000000000000000000000000000000000000000"), "localhost:1111")
		c2 := NewContact(NewKademliaID("2000000000000000000000000000000000000000000000000000000000000000"), "localhost:2222")

		rt := NewRoutingTable(me)

		rt.AddContact(c1)
		rt.AddContact(c2)

		target := NewRandomKademliaID()

		contacts := rt.FindClosestContacts(target, 20)

		if len(contacts) != 2 {
			t.Errorf("expected 2 contacts, got %d", len(contacts))
		}
	})

	t.Run("Ask for less contacts than exist and check order", func(t *testing.T) {
		// Add contacts with known distances to target
		target := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")

		cNear := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001"), "localhost:8888") // dist 1
		cMid := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002"), "localhost:8889")  // dist 2
		cFar := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000004"), "localhost:8880")  // dist 4

		rt := NewRoutingTable(me)
		rt.AddContact(cFar)
		rt.AddContact(cNear)
		rt.AddContact(cMid)

		// Ask only for top 2
		closest := rt.FindClosestContacts(target, 2)
		if len(closest) != 2 {
			t.Fatalf("expected 2 contacts, got %d", len(closest))
		}

		if !closest[0].ID.Equals(cNear.ID) ||
			!closest[1].ID.Equals(cMid.
				ID) {
			t.Errorf("expected [cNear, cMid], got [%s, %s]",
				closest[0].ID,
				closest[1].ID)
		}
	})

	t.Run("Search in neighbour buckets", func(t *testing.T) {
		rt := NewRoutingTable(me)

		// Target belongs to bucket 8 -> byte 1 = 0x80
		target := NewKademliaID("0080000000000000000000000000000000000000000000000000000000000000")

		// cLower belongs to bucket 0 -> byte 0 = 0x80, which is index < 8
		cLower := NewContact(NewKademliaID("8000000000000000000000000000000000000000000000000000000000000000"), "localhost:1001")

		// cHigher belongs to bucket 16 -> byte 2 = 0x80, which is index > 8
		cHigher := NewContact(NewKademliaID("0000800000000000000000000000000000000000000000000000000000000000"), "localhost:1002")

		rt.AddContact(cLower)
		rt.AddContact(cHigher)

		// Bucket 8 is empty, so FindClosestContacts must search both downwards/left (to bucket 0)
		// and upwards/right (to bucket 16) to find 2 contacts.
		contacts := rt.FindClosestContacts(target, 2)

		if len(contacts) != 2 {
			t.Fatalf("expected 2 contacts from neighbouring buckets, got %d", len(contacts))
		}

		foundLower := false
		foundHigher := false
		for _, c := range contacts {
			if c.ID.Equals(cLower.ID) {
				foundLower = true
			}
			if c.ID.Equals(cHigher.ID) {
				foundHigher = true
			}
		}

		if !foundLower || !foundHigher {
			t.Errorf("expected to find both cLower and cHigher in search results")
		}
	})

	t.Run("GetAllContacts returns all added contacts", func(t *testing.T) {
		rt := NewRoutingTable(me)
		if contacts := rt.GetAllContacts(); len(contacts) != 0 {
			t.Errorf("expected empty routing table to return 0 contacts, got %d", len(contacts))
		}

		c1 := NewContact(NewKademliaID("1000000000000000000000000000000000000000000000000000000000000000"), "127.0.0.1:8001")
		c2 := NewContact(NewKademliaID("2000000000000000000000000000000000000000000000000000000000000000"), "127.0.0.1:8002")

		rt.AddContact(c1)
		rt.AddContact(c2)

		all := rt.GetAllContacts()
		if len(all) != 2 {
			t.Fatalf("expected 2 contacts, got %d", len(all))
		}
	})

	t.Run("GetClosestNonEmptyBucketIndex on empty table returns -1", func(t *testing.T) {
		rt := NewRoutingTable(me)
		if idx := rt.GetClosestNonEmptyBucketIndex(); idx != -1 {
			t.Errorf("expected -1 on empty table, got %d", idx)
		}
	})

	t.Run("GetClosestNonEmptyBucketIndex returns highest non-empty bucket index", func(t *testing.T) {
		rt := NewRoutingTable(me)

		// cLower belongs to bucket 0
		cLower := NewContact(NewKademliaID("8000000000000000000000000000000000000000000000000000000000000000"), "localhost:1001")
		rt.AddContact(cLower)

		if idx := rt.GetClosestNonEmptyBucketIndex(); idx != 0 {
			t.Errorf("expected index 0, got %d", idx)
		}

		// cHigher belongs to bucket 16
		cHigher := NewContact(NewKademliaID("0000800000000000000000000000000000000000000000000000000000000000"), "localhost:1002")
		rt.AddContact(cHigher)

		if idx := rt.GetClosestNonEmptyBucketIndex(); idx != 16 {
			t.Errorf("expected index 16 (closest / highest), got %d", idx)
		}
	})

	t.Run("IsBucketEmpty checks bucket state and out of bounds", func(t *testing.T) {
		rt := NewRoutingTable(me)
		if !rt.IsBucketEmpty(0) {
			t.Errorf("expected bucket 0 to be empty")
		}

		c := NewContact(NewKademliaID("8000000000000000000000000000000000000000000000000000000000000000"), "localhost:1001")
		rt.AddContact(c)

		if rt.IsBucketEmpty(0) {
			t.Errorf("expected bucket 0 to NOT be empty")
		}
		if !rt.IsBucketEmpty(-1) {
			t.Errorf("expected out of bounds -1 to report empty")
		}
		if !rt.IsBucketEmpty(300) {
			t.Errorf("expected out of bounds 300 to report empty")
		}
	})

	t.Run("RemoveContact evicts contact and updates bucket", func(t *testing.T) {
		rt := NewRoutingTable(me)
		c := NewContact(NewKademliaID("8000000000000000000000000000000000000000000000000000000000000000"), "localhost:1001")
		rt.AddContact(c)

		if rt.IsBucketEmpty(0) {
			t.Fatalf("expected bucket 0 to contain contact")
		}

		// Evict contact
		if !rt.RemoveContact(c) {
			t.Errorf("expected RemoveContact to return true for existing contact")
		}

		if !rt.IsBucketEmpty(0) {
			t.Errorf("expected bucket 0 to be empty after eviction")
		}

		// Second eviction should return false
		if rt.RemoveContact(c) {
			t.Errorf("expected RemoveContact to return false for already evicted contact")
		}

		// Evict nil contact
		if rt.RemoveContact(Contact{}) {
			t.Errorf("expected RemoveContact with nil ID to return false")
		}
	})
}

func TestRoutingTable_UpdateWithPing(t *testing.T) {
	me := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000"), "localhost:6767")

	t.Run("Eviction occurs when oldest contact fails ping", func(t *testing.T) {
		rt := NewRoutingTable(me)

		// Fill bucket 0 (differs at MSB: starts with '8') with 10 contacts
		var contacts []Contact
		for i := 0; i < bucketSize; i++ {
			idHex := fmt.Sprintf("800000000000000000000000000000000000000000000000000000000000000%x", i+1)
			c := NewContact(NewKademliaID(idHex), fmt.Sprintf("10.0.0.%d:8000", i+1))
			rt.AddContact(c)
			contacts = append(contacts, c)
		}

		// The first added contact (contacts[0]) is at the tail/back
		oldest := contacts[0]

		// 11th candidate arrives for bucket 0
		candidate := NewContact(NewKademliaID("80000000000000000000000000000000000000000000000000000000000000ff"), "10.0.0.99:8000")

		pingedCount := 0
		pinger := func(target Contact) error {
			pingedCount++
			if !target.ID.Equals(oldest.ID) {
				t.Errorf("expected pinger to ping oldest contact %v, got %v", oldest.ID, target.ID)
			}
			return fmt.Errorf("ping timeout: node unreachable")
		}

		rt.UpdateWithPing(candidate, pinger)
		rt.WaitEviction()

		if pingedCount != 1 {
			t.Fatalf("expected exactly 1 ping to be dispatched, got %d", pingedCount)
		}

		bucket0 := rt.buckets[0]
		if bucket0.Len() != bucketSize {
			t.Errorf("expected bucket len to remain %d, got %d", bucketSize, bucket0.Len())
		}

		// Oldest must be evicted
		for e := bucket0.list.Front(); e != nil; e = e.Next() {
			if e.Value.(Contact).ID.Equals(oldest.ID) {
				t.Errorf("expected oldest contact %s to be evicted, but still present", oldest.ID)
			}
		}

		// Candidate must be added
		foundCandidate := false
		for e := bucket0.list.Front(); e != nil; e = e.Next() {
			if e.Value.(Contact).ID.Equals(candidate.ID) {
				foundCandidate = true
				break
			}
		}
		if !foundCandidate {
			t.Errorf("expected candidate %s to be added after eviction", candidate.ID)
		}
	})

	t.Run("Oldest contact is promoted and candidate discarded when ping succeeds", func(t *testing.T) {
		rt := NewRoutingTable(me)

		// Fill bucket 0 with 10 contacts
		var contacts []Contact
		for i := 0; i < bucketSize; i++ {
			idHex := fmt.Sprintf("800000000000000000000000000000000000000000000000000000000000000%x", i+1)
			c := NewContact(NewKademliaID(idHex), fmt.Sprintf("10.0.0.%d:8000", i+1))
			rt.AddContact(c)
			contacts = append(contacts, c)
		}

		oldest := contacts[0]
		candidate := NewContact(NewKademliaID("80000000000000000000000000000000000000000000000000000000000000ff"), "10.0.0.99:8000")

		pinger := func(target Contact) error {
			return nil // ping success (node alive)
		}

		rt.UpdateWithPing(candidate, pinger)
		rt.WaitEviction()

		bucket0 := rt.buckets[0]
		if bucket0.Len() != bucketSize {
			t.Errorf("expected bucket len %d, got %d", bucketSize, bucket0.Len())
		}

		// Oldest must now be at the front of bucket 0
		front := bucket0.list.Front().Value.(Contact)
		if !front.ID.Equals(oldest.ID) {
			t.Errorf("expected oldest contact %s to be promoted to front, got %s", oldest.ID, front.ID)
		}

		// Candidate must NOT be present in active bucket (stays in replacement cache)
		for e := bucket0.list.Front(); e != nil; e = e.Next() {
			if e.Value.(Contact).ID.Equals(candidate.ID) {
				t.Errorf("expected candidate %s to not be in active bucket, but was added", candidate.ID)
			}
		}

		// Candidate must be in replacement cache waiting for future evictions
		queued := rt.GetReplacementCandidates(0)
		if len(queued) != 1 || !queued[0].ID.Equals(candidate.ID) {
			t.Errorf("expected candidate to be queued in replacement cache, got %v", queued)
		}
	})

	t.Run("FIFO promotion order when multiple candidates arrive during in-flight ping", func(t *testing.T) {
		rt := NewRoutingTable(me)

		// Fill bucket 0 with 10 contacts
		for i := 0; i < bucketSize; i++ {
			idHex := fmt.Sprintf("800000000000000000000000000000000000000000000000000000000000000%x", i+1)
			c := NewContact(NewKademliaID(idHex), fmt.Sprintf("10.0.0.%d:8000", i+1))
			rt.AddContact(c)
		}

		// Candidates A, B, C for bucket 0
		candA := NewContact(NewKademliaID("80000000000000000000000000000000000000000000000000000000000000aa"), "10.0.0.101:8000")
		candB := NewContact(NewKademliaID("80000000000000000000000000000000000000000000000000000000000000bb"), "10.0.0.102:8000")
		candC := NewContact(NewKademliaID("80000000000000000000000000000000000000000000000000000000000000cc"), "10.0.0.103:8000")

		pingRelease := make(chan struct{})
		pinger := func(target Contact) error {
			<-pingRelease
			return fmt.Errorf("timeout: dead node")
		}

		// candA arrives -> triggers ping
		rt.UpdateWithPing(candA, pinger)

		// While ping is in flight, candB and candC arrive
		rt.UpdateWithPing(candB, pinger)
		rt.UpdateWithPing(candC, pinger)

		// Verify replacement queue currently holds [candA, candB, candC]
		queuedBefore := rt.GetReplacementCandidates(0)
		if len(queuedBefore) != 3 {
			t.Fatalf("expected 3 candidates in replacement queue, got %d", len(queuedBefore))
		}

		// Release the ping (fails)
		close(pingRelease)
		rt.WaitEviction()

		// FIFO: candA (first to arrive) MUST be promoted into active bucket!
		bucket0 := rt.buckets[0]
		foundA := false
		for e := bucket0.list.Front(); e != nil; e = e.Next() {
			if e.Value.(Contact).ID.Equals(candA.ID) {
				foundA = true
				break
			}
		}
		if !foundA {
			t.Errorf("expected candA (first to arrive) to be promoted into active bucket")
		}

		// candB and candC must remain in the replacement queue in FIFO order [candB, candC]
		queuedAfter := rt.GetReplacementCandidates(0)
		if len(queuedAfter) != 2 {
			t.Fatalf("expected 2 candidates remaining in replacement queue, got %d", len(queuedAfter))
		}
		if !queuedAfter[0].ID.Equals(candB.ID) || !queuedAfter[1].ID.Equals(candC.ID) {
			t.Errorf("expected remaining replacement queue to be [candB, candC], got %v", queuedAfter)
		}
	})

	t.Run("Replacement cache is bounded by replacementCacheSize", func(t *testing.T) {
		rt := NewRoutingTable(me)

		// Fill bucket 0 with 10 contacts
		for i := 0; i < bucketSize; i++ {
			idHex := fmt.Sprintf("800000000000000000000000000000000000000000000000000000000000000%x", i+1)
			c := NewContact(NewKademliaID(idHex), fmt.Sprintf("10.0.0.%d:8000", i+1))
			rt.AddContact(c)
		}

		pingerBlock := make(chan struct{})
		pinger := func(target Contact) error {
			<-pingerBlock
			return nil
		}

		// Add 15 distinct candidates to full bucket 0
		for i := 0; i < 15; i++ {
			idHex := fmt.Sprintf("80000000000000000000000000000000000000000000000000000000000000%02x", i+16)
			cand := NewContact(NewKademliaID(idHex), fmt.Sprintf("10.0.1.%d:8000", i))
			rt.UpdateWithPing(cand, pinger)
		}

		queued := rt.GetReplacementCandidates(0)
		if len(queued) != replacementCacheSize {
			t.Errorf("expected replacement cache size to be bounded at %d, got %d", replacementCacheSize, len(queued))
		}

		close(pingerBlock)
		rt.WaitEviction()
	})
}
