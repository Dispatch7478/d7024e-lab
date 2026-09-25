package kademlia

import (
	"log/slog"
	"sync"
)

const (
	bucketSize           = 10
	replacementCacheSize = 10
)

// RoutingTable definition
// keeps a refrence contact of me and an array of buckets
type RoutingTable struct {
	me Contact
	// 256 buckets, one for every bit position (0 to 255).
	// so  at most 256*20 = 5,120 total contacts per table.
	buckets [IDLength * 8]*bucket
	mu      sync.RWMutex

	// Eviction ping coordination (FIFO replacement cache per bucket)
	evictMu      sync.Mutex
	inFlight     map[int]bool
	replacements map[int][]Contact
	evictWg      sync.WaitGroup
}

// NewRoutingTable returns a new instance of a RoutingTable
func NewRoutingTable(me Contact) *RoutingTable {
	routingTable := &RoutingTable{
		me:           me,
		inFlight:     make(map[int]bool),
		replacements: make(map[int][]Contact),
	}
	for i := range IDLength * 8 {
		routingTable.buckets[i] = newBucket()
	}
	return routingTable
}

// AddContact add a new contact to the correct Bucket
func (routingTable *RoutingTable) AddContact(contact Contact) {
	if contact.ID == nil {
		return
	}
	routingTable.mu.Lock()
	defer routingTable.mu.Unlock()

	bucketIndex := routingTable.GetBucketIndex(contact.ID)
	bucket := routingTable.buckets[bucketIndex]
	if !bucket.AddContact(contact) {
		slog.Debug("routing table bucket full, contact not added",
			"event", "bucket_full",
			"contact_id", contact.ID.String(),
			"bucket_index", bucketIndex,
		)
	}
}

// UpdateWithPing implements Kademlia's ping-based eviction mechanism.
// If the bucket has room or the candidate already exists, it updates the bucket immediately.
// If the bucket is full, it retains the candidate as a replacement and asynchronously pings
// the least-recently seen (oldest) contact in the bucket.
// If the oldest contact fails to respond, it is evicted and replaced by the candidate.
// If the oldest contact responds, it is promoted to the head and the candidate is discarded.
func (routingTable *RoutingTable) UpdateWithPing(candidate Contact, pinger func(Contact) error) {
	if candidate.ID == nil || (routingTable.me.ID != nil && candidate.ID.Equals(routingTable.me.ID)) {
		return
	}

	routingTable.mu.Lock()
	bucketIndex := routingTable.GetBucketIndex(candidate.ID)
	bucket := routingTable.buckets[bucketIndex]

	// Try adding or promoting candidate
	if bucket.AddContact(candidate) {
		routingTable.mu.Unlock()
		return
	}

	// Bucket is full. Get the least-recently seen contact (the tail)
	oldestPtr := bucket.GetOldestContact()
	routingTable.mu.Unlock()

	if oldestPtr == nil || pinger == nil {
		slog.Debug("routing table bucket full, candidate dropped",
			"event", "bucket_full",
			"contact_id", candidate.ID.String(),
			"bucket_index", bucketIndex,
		)
		return
	}

	oldest := *oldestPtr

	// Coordinate eviction probe and enqueue candidate into replacement cache (FIFO)
	routingTable.evictMu.Lock()
	queue := routingTable.replacements[bucketIndex]
	alreadyInCache := false
	for _, c := range queue {
		if c.ID != nil && c.ID.Equals(candidate.ID) {
			alreadyInCache = true
			break
		}
	}
	if !alreadyInCache {
		if len(queue) >= replacementCacheSize {
			// Bounded cache: drop the oldest entry to prevent unbounded growth
			queue = queue[1:]
		}
		queue = append(queue, candidate)
		routingTable.replacements[bucketIndex] = queue
	}

	if routingTable.inFlight[bucketIndex] {
		// A probe is already active for this bucket; candidate safely queued in FIFO replacement cache
		routingTable.evictMu.Unlock()
		return
	}
	routingTable.inFlight[bucketIndex] = true
	routingTable.evictWg.Add(1)
	routingTable.evictMu.Unlock()

	// Launch asynchronous eviction probe
	go func(bIdx int, target Contact) {
		defer routingTable.evictWg.Done()
		defer func() {
			routingTable.evictMu.Lock()
			delete(routingTable.inFlight, bIdx)
			routingTable.evictMu.Unlock()
		}()

		err := pinger(target)
		if err != nil {
			// Oldest node failed to respond -> dead. Evict it.
			slog.Warn("dead node detected during eviction probe",
				"event", "dead_node_detected",
				"type", "eviction_probe",
				"contact_id", target.ID.String(),
				"address", target.Address,
				"bucket_index", bIdx,
				"err", err.Error(),
			)

			// Remove dead contact from the routing table
			routingTable.RemoveContact(target)

			// Pop the first candidate from the replacement queue (FIFO)
			routingTable.evictMu.Lock()
			var repl Contact
			var hasRepl bool
			if len(routingTable.replacements[bIdx]) > 0 {
				repl = routingTable.replacements[bIdx][0]
				routingTable.replacements[bIdx] = routingTable.replacements[bIdx][1:]
				hasRepl = true
			}
			routingTable.evictMu.Unlock()

			if hasRepl {
				routingTable.AddContact(repl)
			}
		} else {
			// Oldest node responded! Promote it to the front
			routingTable.mu.Lock()
			routingTable.buckets[bIdx].AddContact(target)
			routingTable.mu.Unlock()

			// The replacement candidates remain queued in replacements[bIdx] for future evictions.
		}
	}(bucketIndex, oldest)
}

// GetReplacementCandidates returns a copy of queued replacement candidates for bucketIndex.
func (routingTable *RoutingTable) GetReplacementCandidates(bucketIndex int) []Contact {
	routingTable.evictMu.Lock()
	defer routingTable.evictMu.Unlock()

	queue := routingTable.replacements[bucketIndex]
	res := make([]Contact, len(queue))
	copy(res, queue)
	return res
}

// WaitEviction blocks until all active background eviction probes complete.
func (routingTable *RoutingTable) WaitEviction() {
	routingTable.evictWg.Wait()
}

// RemoveContact removes a contact from its bucket and logs the eviction event.
func (routingTable *RoutingTable) RemoveContact(contact Contact) bool {
	routingTable.mu.Lock()
	defer routingTable.mu.Unlock()

	if contact.ID == nil {
		return false
	}

	bucketIndex := routingTable.GetBucketIndex(contact.ID)
	bucket := routingTable.buckets[bucketIndex]
	removed := bucket.RemoveContact(contact)
	if removed {
		slog.Info("routing table eviction",
			"event", "routing_table_eviction",
			"contact_id", contact.ID.String(),
			"address", contact.Address,
			"bucket_index", bucketIndex,
		)
	}
	return removed
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
