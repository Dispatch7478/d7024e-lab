package kademlia

import (
	"testing"
)

func TestShortlist(t *testing.T) {
	target := NewKademliaID("1000000000000000000000000000000000000000000000000000000000000000")
	meID := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")

	t.Run("Self contact is ignored", func(t *testing.T) {
		shortlist := NewShortlist(target, meID)
		meContact := NewContact(meID, "127.0.0.1:8000")
		shortlist.Add(meContact)
		if shortlist.Len() != 0 {
			t.Errorf("expected self contact to be ignored, got len %d", shortlist.Len())
		}
	})

	t.Run("Nil ID contact is ignored", func(t *testing.T) {
		shortlist := NewShortlist(target, meID)
		nilContact := Contact{ID: nil, Address: "127.0.0.1:8001"}
		shortlist.Add(nilContact)
		if shortlist.Len() != 0 {
			t.Errorf("expected nil ID contact to be ignored, got len %d", shortlist.Len())
		}
	})

	t.Run("Add valid contact starts with StatusUnqueried", func(t *testing.T) {
		shortlist := NewShortlist(target, meID)
		c1 := NewContact(NewKademliaID("2000000000000000000000000000000000000000000000000000000000000000"), "127.0.0.1:8002")
		shortlist.Add(c1)
		if shortlist.Len() != 1 {
			t.Fatalf("expected len 1, got %d", shortlist.Len())
		}
		cand, ok := shortlist.getCandidate(c1.ID)
		if !ok || cand == nil {
			t.Fatalf("expected to find candidate in shortlist")
		}
		if cand.Status != StatusUnqueried {
			t.Errorf("expected StatusUnqueried, got %v", cand.Status)
		}
	})

	t.Run("Duplicate contact does not overwrite status", func(t *testing.T) {
		shortlist := NewShortlist(target, meID)
		c1 := NewContact(NewKademliaID("2000000000000000000000000000000000000000000000000000000000000000"), "127.0.0.1:8002")
		shortlist.Add(c1)
		shortlist.MarkQueried(c1.ID)
		// Re-add duplicate
		shortlist.Add(c1)
		cand, _ := shortlist.getCandidate(c1.ID)
		if cand.Status != StatusQueried {
			t.Errorf("expected status to remain QUERIED, got %v", cand.Status)
		}
	})

	t.Run("getCandidate with nil ID returns false", func(t *testing.T) {
		shortlist := NewShortlist(target, meID)
		if c, ok := shortlist.getCandidate(nil); ok || c != nil {
			t.Errorf("expected false and nil for nil ID candidate query")
		}
	})

	t.Run("MarkQueried and MarkUnresponsive transitions", func(t *testing.T) {
		shortlist := NewShortlist(target, nil)
		c1 := NewContact(NewKademliaID("2000000000000000000000000000000000000000000000000000000000000000"), "127.0.0.1:8002")
		shortlist.Add(c1)

		// Nil checks should not panic
		shortlist.MarkQueried(nil)
		shortlist.MarkUnresponsive(nil)

		shortlist.MarkQueried(c1.ID)
		cand, _ := shortlist.getCandidate(c1.ID)
		if cand.Status != StatusQueried {
			t.Errorf("expected StatusQueried, got %v", cand.Status)
		}

		shortlist.MarkUnresponsive(c1.ID)
		cand, _ = shortlist.getCandidate(c1.ID)
		if cand.Status != StatusUnresponsive {
			t.Errorf("expected StatusUnresponsive, got %v", cand.Status)
		}
	})

	t.Run("Active candidates are sorted by XOR distance to target", func(t *testing.T) {
		zeroTarget := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")
		shortlist := NewShortlist(zeroTarget, nil)

		cNear := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001"), "127.0.0.1:8001")
		cMid := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002"), "127.0.0.1:8002")
		cFar := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000004"), "127.0.0.1:8003")

		shortlist.Add(cFar, cNear, cMid)

		active := shortlist.GetActiveCandidates()
		if len(active) != 3 {
			t.Fatalf("expected 3 active candidates, got %d", len(active))
		}
		if !active[0].Contact.ID.Equals(cNear.ID) || !active[1].Contact.ID.Equals(cMid.ID) || !active[2].Contact.ID.Equals(cFar.ID) {
			t.Errorf("expected candidates sorted near, mid, far")
		}
	})

	t.Run("Unresponsive candidates are excluded from active list", func(t *testing.T) {
		zeroTarget := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")
		shortlist := NewShortlist(zeroTarget, nil)

		c1 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001"), "127.0.0.1:8001")
		c2 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002"), "127.0.0.1:8002")
		shortlist.Add(c1, c2)

		shortlist.MarkUnresponsive(c1.ID)

		active := shortlist.GetActiveCandidates()
		if len(active) != 1 || !active[0].Contact.ID.Equals(c2.ID) {
			t.Errorf("expected only c2 to be active, got %v", active)
		}
	})

	t.Run("GetClosestUnqueried returns closest unqueried within limit", func(t *testing.T) {
		zeroTarget := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")
		shortlist := NewShortlist(zeroTarget, nil)

		cNear := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001"), "127.0.0.1:8001")
		cMid := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002"), "127.0.0.1:8002")
		cFar := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000004"), "127.0.0.1:8003")
		shortlist.Add(cNear, cMid, cFar)

		// Mark nearest as already queried
		shortlist.MarkQueried(cNear.ID)

		// Ask for up to 2 unqueried within top 3
		unqueried := shortlist.GetClosestUnqueried(2, 3)
		if len(unqueried) != 2 {
			t.Fatalf("expected 2 unqueried, got %d", len(unqueried))
		}
		if !unqueried[0].ID.Equals(cMid.ID) || !unqueried[1].ID.Equals(cFar.ID) {
			t.Errorf("expected cMid and cFar, got %v", unqueried)
		}
	})

	t.Run("HasUnqueriedInTopK termination condition", func(t *testing.T) {
		zeroTarget := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")
		shortlist := NewShortlist(zeroTarget, nil)

		c1 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001"), "127.0.0.1:8001")
		c2 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002"), "127.0.0.1:8002")
		shortlist.Add(c1, c2)

		if !shortlist.HasUnqueriedInTopK(2) {
			t.Errorf("expected true when candidates are unqueried")
		}

		shortlist.MarkQueried(c1.ID)
		shortlist.MarkQueried(c2.ID)

		if shortlist.HasUnqueriedInTopK(2) {
			t.Errorf("expected false when all candidates in top k are queried")
		}
	})

	t.Run("GetClosestQueried returns only queried contacts up to limit", func(t *testing.T) {
		zeroTarget := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")
		shortlist := NewShortlist(zeroTarget, nil)

		c1 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001"), "127.0.0.1:8001")
		c2 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002"), "127.0.0.1:8002")
		c3 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000004"), "127.0.0.1:8003")
		shortlist.Add(c1, c2, c3)

		shortlist.MarkQueried(c1.ID)
		shortlist.MarkQueried(c3.ID)
		// c2 remains unqueried

		queried := shortlist.GetClosestQueried(10)
		if len(queried) != 2 {
			t.Fatalf("expected 2 queried contacts, got %d", len(queried))
		}
		if !queried[0].ID.Equals(c1.ID) || !queried[1].ID.Equals(c3.ID) {
			t.Errorf("expected c1 and c3 in queried results")
		}
	})
}
