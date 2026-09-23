package kademlia

import (
	"container/list"
)

// bucket definition
// contains a List
type bucket struct {
	list *list.List
}

// newBucket returns a new instance of a bucket
func newBucket() *bucket {
	bucket := &bucket{}
	bucket.list = list.New()
	return bucket
}

// AddContact adds the Contact to the front of the bucket
// or moves it to the front of the bucket if it already existed.
// Returns true if added or promoted, false if rejected because the bucket is full.
func (bucket *bucket) AddContact(contact Contact) bool {
	var element *list.Element
	for e := bucket.list.Front(); e != nil; e = e.Next() {
		nodeID := e.Value.(Contact).ID

		if (contact).ID.Equals(nodeID) {
			element = e
		}
	}

	if element == nil {
		if bucket.list.Len() < bucketSize {
			bucket.list.PushFront(contact)
			return true
		}
		return false
	} else {
		bucket.list.MoveToFront(element)
		return true
	}
}

// RemoveContact removes a contact from the bucket if present.
// Returns true if the contact was found and removed, false otherwise.
func (bucket *bucket) RemoveContact(contact Contact) bool {
	if contact.ID == nil {
		return false
	}
	for e := bucket.list.Front(); e != nil; e = e.Next() {
		nodeID := e.Value.(Contact).ID
		if nodeID != nil && contact.ID.Equals(nodeID) {
			bucket.list.Remove(e)
			return true
		}
	}
	return false
}

// GetOldestContact returns a copy of the least-recently seen contact (at the back of the list),
// or nil if the bucket is empty.
func (bucket *bucket) GetOldestContact() *Contact {
	if bucket.list.Len() == 0 {
		return nil
	}
	tail := bucket.list.Back().Value.(Contact)
	return &tail
}

// GetContactAndCalcDistance returns an array of Contacts where
// the distance has already been calculated
func (bucket *bucket) GetContactAndCalcDistance(target *KademliaID) []Contact {
	var contacts []Contact

	for elt := bucket.list.Front(); elt != nil; elt = elt.Next() {
		contact := elt.Value.(Contact)
		contact.CalcDistance(target)
		contacts = append(contacts, contact)
	}

	return contacts
}

// Len return the size of the bucket
func (bucket *bucket) Len() int {
	return bucket.list.Len()
}
