package kademlia

import "sync"

const bucketSize = 10

// RoutingTable definition
// keeps a refrence contact of me and an array of buckets
type RoutingTable struct {
	me Contact
	// 256 buckets, one for every bit position (0 to 255).
	// so  at most 256*20 = 5,120 total contacts per table.
	buckets [IDLength * 8]*bucket
	mu      sync.RWMutex
}

// NewRoutingTable returns a new instance of a RoutingTable
func NewRoutingTable(me Contact) *RoutingTable {
	routingTable := &RoutingTable{}
	for i := range IDLength * 8 {
		routingTable.buckets[i] = newBucket()
	}
	routingTable.me = me
	return routingTable
}

// AddContact add a new contact to the correct Bucket
func (routingTable *RoutingTable) AddContact(contact Contact) {
	routingTable.mu.Lock()
	defer routingTable.mu.Unlock()

	bucketIndex := routingTable.GetBucketIndex(contact.ID)
	bucket := routingTable.buckets[bucketIndex]
	bucket.AddContact(contact)
}

// FindClosestContacts finds the count closest Contacts to the target in the RoutingTable
func (routingTable *RoutingTable) FindClosestContacts(target *KademliaID, count int) []Contact {
	routingTable.mu.RLock()
	defer routingTable.mu.RUnlock()

	var candidates ContactCandidates
	bucketIndex := routingTable.GetBucketIndex(target)
	bucket := routingTable.buckets[bucketIndex]

	candidates.Append(bucket.GetContactAndCalcDistance(target))

	for i := 1; (bucketIndex-i >= 0 || bucketIndex+i < IDLength*8) && candidates.Len() < count; i++ {
		if bucketIndex-i >= 0 {
			bucket = routingTable.buckets[bucketIndex-i]
			candidates.Append(bucket.GetContactAndCalcDistance(target))
		}
		if bucketIndex+i < IDLength*8 {
			bucket = routingTable.buckets[bucketIndex+i]
			candidates.Append(bucket.GetContactAndCalcDistance(target))
		}
	}

	candidates.Sort()

	if count > candidates.Len() {
		count = candidates.Len()
	}

	return candidates.GetContacts(count)
}

// getBucketIndex get the correct Bucket index for the KademliaID
func (routingTable *RoutingTable) GetBucketIndex(id *KademliaID) int {
	distance := id.CalcDistance(routingTable.me.ID)
	for i := range IDLength { // bytes 0 to 32
		for j := range 8 { // bits in byte i
			// Check the shared prefix, e.g.,
			// msb = 1 -> no prefix so bucket 0
			// msb = 0 and second msb = 1 -> 1-bit prefix so bucket 1
			// Stops when the firsts bit that differs is found.
			if (distance[i]>>uint8(7-j))&0x1 != 0 {
				// Some sort of global index?
				return i*8 + j
			}
		}
	}
	// Same id -> me.
	return IDLength*8 - 1
}

// GetAllContacts returns a list of all active contacts stored across all buckets in a routing table
func (routingTable *RoutingTable) GetAllContacts() []Contact {
	routingTable.mu.RLock()
	defer routingTable.mu.RUnlock()

	var contacts []Contact
	for _, bucket := range routingTable.buckets {
		for element := bucket.list.Front(); element != nil; element = element.Next() {
			if contact, ok := element.Value.(Contact); ok {
				contacts = append(contacts, contact)
			}
		}
	}
	return contacts
}

// GetClosestNonEmptyBucketIndex returns the highest bucket index that contains at least
// one contact (i.e. the bucket with contacts closest to the local node).
// Returns -1 if all buckets are empty.
func (routingTable *RoutingTable) GetClosestNonEmptyBucketIndex() int {
	routingTable.mu.RLock()
	defer routingTable.mu.RUnlock()

	for i := IDLength*8 - 1; i >= 0; i-- {
		if routingTable.buckets[i].Len() > 0 {
			return i
		}
	}
	return -1
}

// IsBucketEmpty reports whether the bucket at index is empty.
// Returns true if index is out of bounds or the bucket has no contacts.
func (routingTable *RoutingTable) IsBucketEmpty(index int) bool {
	routingTable.mu.RLock()
	defer routingTable.mu.RUnlock()

	if index < 0 || index >= IDLength*8 {
		return true
	}
	return routingTable.buckets[index].Len() == 0
}
