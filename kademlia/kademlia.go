package kademlia

import (
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"
)

const (
	defaultAlpha               = 3
	DefaultReplicationInterval = 1 * time.Hour
)

var (
	// ErrValueNotFound is returned when an iterative value lookup fails to locate the key.
	ErrValueNotFound = fmt.Errorf("value not found in DHT")
)

// Kademlia represents a node in the Kademlia network.
type Kademlia struct {
	Me                  Contact
	RoutingTable        *RoutingTable
	Network             Network
	DataStore           *DataStore
	alpha               int
	workerMu            sync.Mutex
	replicationInterval time.Duration
	stopReplication     chan struct{}
	replicateWg         sync.WaitGroup
}

// NewKademlia returns a new Kademlia instance.
func NewKademlia(me Contact, network Network, routingTable *RoutingTable, ds *DataStore, alpha int) *Kademlia {
	a := defaultAlpha
	if alpha > 0 {
		a = alpha
	}

	return &Kademlia{
		Me:           me,
		Network:      network,
		RoutingTable: routingTable,
		DataStore:    ds,
		alpha:        a,
	}
}

// SendPing sends a ping message to target contact and returns the RPC response.
func (kademlia *Kademlia) SendPing(targetContact *Contact) (*RPCMessage, error) {
	if kademlia.Network == nil {
		return nil, fmt.Errorf("network is nil")
	}
	return kademlia.Network.SendPingMessage(targetContact)
}

// LookupContact performs an iterative node lookup for a target contact using alpha parallel probes.
// This implements the starter code signature.
func (kademlia *Kademlia) LookupContact(target *Contact) []Contact {
	if target == nil {
		return []Contact{}
	}
	return kademlia.LookupContactByID(target.ID)
}

// LookupContactByID performs an iterative node lookup for a target ID using alpha parallel probes.
// The lookup terminates when the k closest nodes have all been queried or no closer nodes are found.
func (kademlia *Kademlia) LookupContactByID(target *KademliaID) []Contact {
	if target == nil {
		return []Contact{}
	}

	if kademlia.RoutingTable == nil {
		return []Contact{}
	}

	// Initialize shortlist from local routing table
	shortlist := NewShortlist(target, kademlia.Me.ID)
	initialContacts := kademlia.RoutingTable.FindClosestContacts(target, bucketSize)
	shortlist.Add(initialContacts...)

	// If no network available or shortlist is empty, return whatever local routing table has
	if kademlia.Network == nil || shortlist.Len() == 0 {
		return kademlia.RoutingTable.FindClosestContacts(target, bucketSize)
	}

	// Iterative lookup loop
	for shortlist.HasUnqueriedInTopK(bucketSize) {
		probes := shortlist.GetClosestUnqueried(kademlia.alpha, bucketSize)
		if len(probes) == 0 {
			break
		}

		type probeResult struct {
			contact  Contact
			contacts []Contact
			err      error
		}

		// Buffered to prevent blocking from an unresponsive node.
		results := make(chan probeResult, len(probes))

		for _, contact := range probes {
			slog.Debug("sending lookup probe",
				"event", "lookup_probe",
				"type", "find_node",
				"target", target.String(),
				"to_id", contact.ID.String(),
				"to_address", contact.Address,
			)
			go func(c Contact) {
				found, err := kademlia.Network.SendFindContactMessage(target, &c)
				results <- probeResult{contact: c, contacts: found, err: err}
			}(contact)
		}

		for i := 0; i < len(probes); i++ {
			res := <-results
			if res.err != nil { // Unresponsive
				slog.Warn("dead node detected",
					"event", "dead_node_detected",
					"type", "find_node",
					"contact_id", res.contact.ID.String(),
					"address", res.contact.Address,
					"err", res.err.Error(),
				)
				shortlist.MarkUnresponsive(res.contact.ID)
			} else { // Responsive
				slog.Debug("received probe response",
					"event", "probe_response",
					"type", "find_node",
					"from_id", res.contact.ID.String(),
					"contacts_count", len(res.contacts),
				)
				shortlist.MarkQueried(res.contact.ID)

				if kademlia.RoutingTable != nil {
					kademlia.RoutingTable.AddContact(res.contact)
				}

				for _, found := range res.contacts {
					// As always just to be sure that it doesn't take itself into account.
					if found.ID == nil || (kademlia.Me.ID != nil && found.ID.Equals(kademlia.Me.ID)) {
						continue
					}

					shortlist.Add(found)
				}
			}
		}
	}

	// Return the bucketSize closest queried responsive nodes
	// which is either k or less
	closest := shortlist.GetClosestQueried(bucketSize)
	if len(closest) > 0 {
		slog.Info("node lookup completed",
			"event", "lookup_success",
			"type", "find_node",
			"target", target.String(),
			"closest_count", len(closest),
		)
	} else {
		slog.Warn("node lookup failed",
			"event", "lookup_failure",
			"type", "find_node",
			"target", target.String(),
		)
	}
	return closest
}

// Join joins the Kademlia network using a bootstrap contact.
// It adds the bootstrap contact to the routing table and runs LookupContact on itself to fill the buckets.
func (kademlia *Kademlia) Join(bootstrap Contact) error {
	if bootstrap.ID == nil {
		return fmt.Errorf("bootstrap contact ID cannot be nil")
	}
	if kademlia.Me.ID != nil && bootstrap.ID.Equals(kademlia.Me.ID) {
		return fmt.Errorf("cannot join network using self as bootstrap")
	}
	if kademlia.RoutingTable == nil {
		return fmt.Errorf("routing table is nil")
	}

	// Join bootstrap.
	kademlia.RoutingTable.AddContact(bootstrap)

	// Lookup self.
	if kademlia.Me.ID != nil {
		kademlia.LookupContactByID(kademlia.Me.ID)

		// Find the highest bucket index that contains a contact, i.e., the closest neighbour's bucket.
		closestBucket := kademlia.RoutingTable.GetClosestNonEmptyBucketIndex()

		// Refresh any empty bucket away from the closest one by performing a lookup on a random
		// contact whose ID belongs to the respective empty bucket range.
		for i := 0; i < closestBucket; i++ {
			if kademlia.RoutingTable.IsBucketEmpty(i) {
				randomTarget := kademlia.generateRandomIDForBucket(i)
				kademlia.LookupContactByID(randomTarget)
			}
		}
	}
	return nil
}

// Store hashes data to create key K = SHA-256(data), finds the k closest nodes to K via LookupContactByID,
// stores the data locally, and sends STORE RPCs to each of the k closest nodes.
func (kademlia *Kademlia) Store(data []byte) (*KademliaID, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot store empty data")
	}

	key := NewKademliaIDFromData(data)

	// Always store in local DataStore
	if kademlia.DataStore != nil {
		if err := kademlia.DataStore.Store(*key, data); err != nil {
			return nil, err
		}
	}

	if kademlia.Network == nil || kademlia.RoutingTable == nil {
		return key, nil
	}

	// Find the k closest nodes to key
	targetContact := NewContact(key, "")
	closest := kademlia.LookupContact(&targetContact)

	// Store on all k closest nodes concurrently
	var wg sync.WaitGroup
	for _, contact := range closest {
		if kademlia.Me.ID != nil && contact.ID != nil && contact.ID.Equals(kademlia.Me.ID) {
			continue
		}
		c := contact
		wg.Go(func() {
			_ = kademlia.Network.SendStoreMessage(&c, key, data)
		})
	}
	wg.Wait()

	slog.Info("stored data locally and across network",
		"event", "store_data",
		"key", key.String(),
		"bytes", len(data),
		"replicas", len(closest),
	)

	return key, nil
}

// LookupData looks up a value by its hexadecimal SHA-256 hash string.
func (kademlia *Kademlia) LookupData(hash string) ([]byte, *Contact, error) {
	key := NewKademliaID(hash)
	return kademlia.LookupDataByID(key)
}

// LookupDataByID executes an iterative value lookup for target ID across the DHT.
// Returns (value, responderContact, nil) if found and verified, or (nil, nil, ErrValueNotFound).
func (kademlia *Kademlia) LookupDataByID(target *KademliaID) ([]byte, *Contact, error) {
	if target == nil {
		return nil, nil, fmt.Errorf("cannot lookup nil target ID")
	}

	// Check local DataStore first
	if kademlia.DataStore != nil {
		if val, found := kademlia.DataStore.Get(*target); found {
			slog.Info("data lookup succeeded (local hit)",
				"event", "lookup_success",
				"type", "find_data",
				"target", target.String(),
				"local", true,
				"bytes", len(val),
			)
			return val, &kademlia.Me, nil
		}
	}

	if kademlia.RoutingTable == nil || kademlia.Network == nil {
		slog.Warn("data lookup failed: network or routing table nil",
			"event", "lookup_failure",
			"type", "find_data",
			"target", target.String(),
		)
		return nil, nil, ErrValueNotFound
	}

	// Initialize candidate shortlist from local routing table
	shortlist := NewShortlist(target, kademlia.Me.ID)
	initialContacts := kademlia.RoutingTable.FindClosestContacts(target, bucketSize)
	shortlist.Add(initialContacts...)

	if shortlist.Len() == 0 {
		slog.Warn("data lookup failed: shortlist empty",
			"event", "lookup_failure",
			"type", "find_data",
			"target", target.String(),
		)
		return nil, nil, ErrValueNotFound
	}

	type probeResult struct {
		contact  Contact
		data     []byte
		contacts []Contact
		err      error
	}

	// Iterative value lookup loop
	for shortlist.HasUnqueriedInTopK(bucketSize) {
		probes := shortlist.GetClosestUnqueried(kademlia.alpha, bucketSize)
		if len(probes) == 0 {
			break
		}

		results := make(chan probeResult, len(probes))

		for _, contact := range probes {
			slog.Debug("sending find_data probe",
				"event", "lookup_probe",
				"type", "find_data",
				"target", target.String(),
				"to_id", contact.ID.String(),
				"to_address", contact.Address,
			)
			go func(c Contact) {
				data, contacts, err := kademlia.Network.SendFindDataMessage(target, &c)
				results <- probeResult{
					contact:  c,
					data:     data,
					contacts: contacts,
					err:      err,
				}
			}(contact)
		}

		for i := 0; i < len(probes); i++ {
			res := <-results
			if res.err != nil {
				slog.Warn("dead node detected during data lookup",
					"event", "dead_node_detected",
					"type", "find_data",
					"contact_id", res.contact.ID.String(),
					"address", res.contact.Address,
					"err", res.err.Error(),
				)
				shortlist.MarkUnresponsive(res.contact.ID)
				continue
			}

			shortlist.MarkQueried(res.contact.ID)

			if kademlia.RoutingTable != nil {
				kademlia.RoutingTable.AddContact(res.contact)
			}

			// Value found on another node.
			if len(res.data) > 0 {
				// Check that K = SHA-256(V)
				expectedHash := NewKademliaIDFromData(res.data)
				if !expectedHash.Equals(target) {
					slog.Error("discarding corrupted value from remote peer: hash mismatch",
						"event", "corrupt_data_discarded",
						"target", target.String(),
						"actual_hash", expectedHash.String(),
						"sender_id", res.contact.ID.String(),
						"sender_address", res.contact.Address,
					)
					// Discard corrupted value and continue searching
					continue
				}

				// Cache locally in DataStore
				if kademlia.DataStore != nil {
					_ = kademlia.DataStore.Store(*target, res.data)
				}

				slog.Info("data lookup succeeded",
					"event", "lookup_success",
					"type", "find_data",
					"target", target.String(),
					"from_id", res.contact.ID.String(),
					"from_address", res.contact.Address,
					"bytes", len(res.data),
				)

				return res.data, &res.contact, nil
			}

			// Remote peer did not have the value; returned closest contacts
			for _, found := range res.contacts {
				if found.ID == nil || (kademlia.Me.ID != nil && found.ID.Equals(kademlia.Me.ID)) {
					continue
				}
				shortlist.Add(found)
			}
		}
	}

	slog.Warn("data lookup failed",
		"event", "lookup_failure",
		"type", "find_data",
		"target", target.String(),
	)
	return nil, nil, ErrValueNotFound
}

// Replicate republishes all locally stored key-value pairs to their k closest nodes.
// "periodically replicate existing key-value pairs so that they are not lost despite churn".
func (kademlia *Kademlia) Replicate() {
	if kademlia.DataStore == nil || kademlia.Network == nil || kademlia.RoutingTable == nil {
		return
	}

	// For every value find the k closest nodes to the key K and store the value in them.
	keys := kademlia.DataStore.GetAllKeys()
	if len(keys) == 0 {
		return
	}

	slog.Info("periodic replication pass started",
		"event", "replication_started",
		"keys_count", len(keys),
	)

	for _, key := range keys {
		val, found := kademlia.DataStore.Get(key)
		if !found {
			continue
		}
		k := key
		targetContact := NewContact(&k, "")
		closest := kademlia.LookupContact(&targetContact)

		var storeWg sync.WaitGroup
		for _, contact := range closest {
			if kademlia.Me.ID != nil && contact.ID != nil && contact.ID.Equals(kademlia.Me.ID) {
				continue
			}
			c := contact
			storeWg.Add(1)
			go func(c Contact, key KademliaID, data []byte) {
				defer storeWg.Done()
				_ = kademlia.Network.SendStoreMessage(&c, &key, data)
			}(c, k, val)
		}
		storeWg.Wait()
	}

	slog.Info("periodic replication pass completed",
		"event", "replication_completed",
		"keys_count", len(keys),
	)
}

// generateRandomIDForBucket returns a random KademliaID that falls within the distance range of bucket index.
func (kademlia *Kademlia) generateRandomIDForBucket(index int) *KademliaID {
	if kademlia.Me.ID == nil || index < 0 || index >= IDLength*8 {
		return NewRandomKademliaID()
	}

	// Start from the local node's ID.
	target := *kademlia.Me.ID
	// Extract the respective byte from the respective 32-byte arrays contains the index bit.
	byteIdx := index / 8
	// Find the bit's power of 2 to build the mask.
	bitOffset := uint(7 - (index % 8))

	// Flip the bit at index so XOR distance differs at this exact bit position.
	target[byteIdx] ^= (1 << bitOffset)

	// Randomize bits less significant than bitOffset in the same byte.
	for b := 0; b < int(bitOffset); b++ {
		if rand.Intn(2) == 1 {
			target[byteIdx] |= (1 << uint(b))
		} else {
			target[byteIdx] &= ^(1 << uint(b))
		}
	}

	// Randomize the rest of the bytes.
	for b := byteIdx + 1; b < IDLength; b++ {
		target[b] = byte(rand.Intn(256))
	}

	return &target
}

// StartReplicationWorker starts a background ticker that periodically replicates data.
func (kademlia *Kademlia) StartReplicationWorker(interval time.Duration) {
	kademlia.workerMu.Lock()
	defer kademlia.workerMu.Unlock()

	// If already running, stop previous worker first
	if kademlia.stopReplication != nil {
		close(kademlia.stopReplication)
		kademlia.replicateWg.Wait()
		kademlia.stopReplication = nil
	}

	if interval <= 0 {
		interval = DefaultReplicationInterval
	}

	kademlia.replicationInterval = interval
	kademlia.stopReplication = make(chan struct{})
	stopCh := kademlia.stopReplication
	kademlia.replicateWg.Add(1)

	go func() {
		defer kademlia.replicateWg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				kademlia.Replicate()
			case <-stopCh:
				return
			}
		}
	}()
}

// StopReplicationWorker halts the replication background worker cleanly.
func (kademlia *Kademlia) StopReplicationWorker() {
	kademlia.workerMu.Lock()
	defer kademlia.workerMu.Unlock()

	if kademlia.stopReplication != nil {
		close(kademlia.stopReplication)
		kademlia.replicateWg.Wait()
		kademlia.stopReplication = nil
	}
}
