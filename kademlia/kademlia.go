package kademlia

import (
	"fmt"
	"log/slog"
)

const defaultAlpha = 1 // 3

// Kademlia represents a node in the Kademlia network.
type Kademlia struct {
	me           Contact
	routingTable *RoutingTable
	network      Network
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
		me:           me,
		network:      network,
		routingTable: routingTable,
		alpha:        a,
	}
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

	if kademlia.routingTable == nil {
		return []Contact{}
	}

	// Initialize shortlist from local routing table
	shortlist := NewShortlist(target, kademlia.me.ID)
	initialContacts := kademlia.routingTable.FindClosestContacts(target, bucketSize)
	shortlist.Add(initialContacts...)

	// If no network available or shortlist is empty, return whatever local routing table has
	if kademlia.network == nil || shortlist.Len() == 0 {
		return kademlia.routingTable.FindClosestContacts(target, bucketSize)
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
				found, err := kademlia.network.SendFindContactMessage(target, &c)
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

				if kademlia.routingTable != nil {
					kademlia.routingTable.AddContact(res.contact)
				}

				for _, found := range res.contacts {
					// As always just to be sure that it doesn't take itself into account.
					if found.ID == nil || (kademlia.me.ID != nil && found.ID.Equals(kademlia.me.ID)) {
						continue
					}

					shortlist.Add(found)

					if kademlia.routingTable != nil {
						kademlia.routingTable.AddContact(found)
					}
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
	if kademlia.me.ID != nil && bootstrap.ID.Equals(kademlia.me.ID) {
		return fmt.Errorf("cannot join network using self as bootstrap")
	}
	if kademlia.routingTable == nil {
		return fmt.Errorf("routing table is nil")
	}

	kademlia.routingTable.AddContact(bootstrap)
	if kademlia.me.ID != nil {
		kademlia.LookupContactByID(kademlia.me.ID)
	}
	return nil
}

func (kademlia *Kademlia) LookupData(hash string) {
	// TODO
}

func (kademlia *Kademlia) Store(data []byte) {
	// TODO
}
