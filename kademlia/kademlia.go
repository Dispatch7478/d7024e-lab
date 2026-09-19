package kademlia

import (
	"fmt"
	"log/slog"
	"math/rand"
)

const defaultAlpha = 3

// Kademlia represents a node in the Kademlia network.
type Kademlia struct {
	Me           Contact
	RoutingTable *RoutingTable
	Network      Network
	alpha        int
}

// NewKademlia returns a new Kademlia instance.
// An optional alpha parameter can configure the concurrency level.
func NewKademlia(me Contact, network Network, routingTable *RoutingTable, alpha int) *Kademlia {
	a := defaultAlpha
	if alpha > 0 {
		a = alpha
	}

	return &Kademlia{
		Me:           me,
		Network:      network,
		RoutingTable: routingTable,
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
			go func(c Contact) {
				found, err := kademlia.Network.SendFindContactMessage(target, &c)
				results <- probeResult{contact: c, contacts: found, err: err}
			}(contact)
		}

		for i := 0; i < len(probes); i++ {
			res := <-results
			if res.err != nil { // Unresponsive
				slog.Error("failed to contact node", slog.Any("contact", res.contact.ID), slog.Any("err", res.err))
				shortlist.MarkUnresponsive(res.contact.ID)
			} else { // Responsive
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
	return shortlist.GetClosestQueried(bucketSize)
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

func (kademlia *Kademlia) LookupData(hash string) {
	// TODO
}

func (kademlia *Kademlia) Store(data []byte) {
	// TODO
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
