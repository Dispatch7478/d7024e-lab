package kademlia

import (
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

	// rt := NewRoutingTable(NewContact(NewKademliaID("FFFFFFFF00000000000000000000000000000000000000000000000000000000"), "localhost:8000"))

	// rt.AddContact(NewContact(NewKademliaID("FFFFFFFF00000000000000000000000000000000000000000000000000000000"), "localhost:8001"))
	// rt.AddContact(NewContact(NewKademliaID("1111111100000000000000000000000000000000000000000000000000000000"), "localhost:8002"))
	// rt.AddContact(NewContact(NewKademliaID("1111111200000000000000000000000000000000000000000000000000000000"), "localhost:8002"))
	// rt.AddContact(NewContact(NewKademliaID("1111111300000000000000000000000000000000000000000000000000000000"), "localhost:8002"))
	// rt.AddContact(NewContact(NewKademliaID("1111111400000000000000000000000000000000000000000000000000000000"), "localhost:8002"))
	// rt.AddContact(NewContact(NewKademliaID("2111111400000000000000000000000000000000000000000000000000000000"), "localhost:8002"))

	// contacts := rt.FindClosestContacts(NewKademliaID("2111111400000000000000000000000000000000000000000000000000000000"), 20)
	// for i := range contacts {
	// 	fmt.Println(contacts[i].String())
	// }

	// // TODO: This is just an example. Make more meaningful assertions.
	// if len(contacts) != 6 {
	// 	t.Fatalf("Expected 6 contacts but instead got %d", len(contacts))
	// }
}
