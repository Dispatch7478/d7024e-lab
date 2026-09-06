package kademlia

import (
	"testing"
)

func TestEmptyBucket(t *testing.T) {
	b := newBucket()

	if b.Len() != 0 {
		t.Errorf("new buckets should be empty")
	}
}

func TestAddContacts(t *testing.T) {
	t.Run("Add unique contacts", func(t *testing.T) {
		bucket := newBucket()

		c1 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001"), "localhost:8081")
		c2 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002"), "localhost:8082")
		c3 := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000003"), "localhost:8083")

		bucket.AddContact(c1)
		bucket.AddContact(c2)
		bucket.AddContact(c3)

		if bucket.Len() != 3 {
			t.Errorf("expected bucket length 3, got %d", bucket.Len())
		}
	})

	t.Run("Add duplicate contact", func(t *testing.T) {
		bucket := newBucket()

		cA := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001"), "localhost:1234")
		cB := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002"), "localhost:5678")

		bucket.AddContact(cA)
		bucket.AddContact(cB)
		// List order is currently is cB in front and cA last

		// Add cA: should not duplicate and should move cA to front
		bucket.AddContact(cA)

		if bucket.Len() != 2 {
			t.Errorf("expected bucket length 2 after adding duplicate contact, got %d", bucket.Len())
		}

		frontContact := bucket.list.Front().Value.(Contact)
		if !frontContact.ID.Equals(cA.ID) {
			t.Errorf("expected contact cA (%s) at the front of bucket, got %s", cA.ID, frontContact.ID)
		}
	})

	t.Run("Capacity limit", func(t *testing.T) {
		bucket := newBucket()

		// Attempt to add 25 distinct contacts into the bucket
		for range 25 {
			id := NewRandomKademliaID()
			c := NewContact(id, "localhost:8000")
			bucket.AddContact(c)
		}

		if bucket.Len() != bucketSize {
			t.Errorf("expected bucket length to be blocked at %d, got %d", bucketSize, bucket.Len())
		}
	})
}

func TestGetContactAndCalcDistance(t *testing.T) {
	bucket := newBucket()
	target := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")

	c := NewContact(NewKademliaID("0000000000000000000000000000000000000000000000000000000000000005"), "localhost:5432")
	bucket.AddContact(c)

	contacts := bucket.GetContactAndCalcDistance(target)

	if len(contacts) != 1 {
		t.Fatalf("expected 1 onlt contact, got %d", len(contacts))
	}

	if contacts[0].distance == nil {
		t.Fatalf("expected contact distance to be calculated, got nil")
	}

	expectedDistance := c.ID.CalcDistance(target)
	if !contacts[0].distance.Equals(expectedDistance) {
		t.Errorf("expected distance %s, got %s", expectedDistance, contacts[0].distance)
	}
}
