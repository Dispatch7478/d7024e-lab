package kademlia

import (
	"fmt"
	"testing"
)

func TestNewContact(t *testing.T) {
	id := NewRandomKademliaID()
	c := NewContact(id, "")

	if c.distance != nil {
		t.Errorf("expected nil distance for new contact")
	}
}

func TestContactCalcDistance(t *testing.T) {
	id1 := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001")
	id2 := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000003")

	c := NewContact(id1, "localhost:6666")
	c.CalcDistance(id2)

	want := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002")

	if c.distance == nil {
		t.Fatalf("expected value for contanct.distance, got nil ")
	}
	if !c.distance.Equals(want) {
		t.Errorf("expected distance %s, got %s", want, c.distance)
	}
}

func TestContactLess(t *testing.T) {
	tar := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")
	id1 := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000100") // 4
	id2 := NewKademliaID("0000000000000000000000000000000000000000000000000000000000001000") // 8

	cClose := NewContact(id1, "localhost:67")
	cFar := NewContact(id2, "localhost:69")

	cClose.CalcDistance(tar)
	cFar.CalcDistance(tar)

	if !cClose.Less(&cFar) {
		t.Errorf("expected cClose to be closer than cFar")
	}

	if cFar.Less(&cClose) {
		t.Errorf("expected cFar to be further away than Cclose")
	}
}

func TestContactString(t *testing.T) {
	hexID := "1111111122222222333333334444444455555555666666667777777788888888"
	id := NewKademliaID(hexID)
	c := NewContact(id, "localhost:420")

	want := fmt.Sprintf(`contact("%s", "%s")`, id, c.Address)
	got := c.String()

	if got != want {
		t.Errorf("expected %s, got %s", want, got)
	}
}

func TestContactCandidates_Sort(t *testing.T) {
	target := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")

	// 3 contacts with distances 5, 1 and 3
	c5 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000005"), "localhost:80")
	c1 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001"), "localhost:443")
	c3 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000003"), "localhost:22")

	c5.CalcDistance(target)
	c1.CalcDistance(target)
	c3.CalcDistance(target)

	var candidates ContactCandidates
	candidates.Append([]Contact{c5, c1, c3})

	candidates.Sort()

	// After sorting, the order should be c1, c3, c5 (distance 1, 3, 5)
	top2 := candidates.GetContacts(2)
	if len(top2) != 2 {
		t.Fatalf("expected 2 contacts, got %d", len(top2))
	}
	if !top2[0].ID.Equals(c1.ID) || !top2[1].ID.Equals(c3.ID) {
		t.Errorf("expected contacts ordered (c1, c3), got (%s, %s)", top2[0].ID, top2[1].ID)
	}
}
