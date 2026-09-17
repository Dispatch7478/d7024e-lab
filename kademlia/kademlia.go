package kademlia

import (
	"log"
	"sync"
)

type Kademlia struct {
	Me						Contact
	RoutingTable	*RoutingTable
	Network				*Network
}

const (
	K = 5
	Alpha = 1
)

// creating a new kademlia instance
func NewKademlia(me Contact) *Kademlia {
	kad := &Kademlia{
		Me: 						me,
		RoutingTable: 	NewRoutingTable(me),
	}
	kad.Network = NewNetwork(kad.HandleIncomingRPC)
	return kad 
}

// handles incoming RPCMessages from network 
func (kad *Kademlia) HandleIncomingRPC (msg RPCMessage) *RPCMessage {

	// udpate local routing table
	if msg.Sender.ID != nil{
		kad.RoutingTable.AddContact(msg.Sender)
	}
	switch msg.Type{
		case "PING": 
			return &RPCMessage{
				Type: 						"PONG",
				TransactionID: 		msg.TransactionID,
				Sender:						kad.Me, 
			} 
		case "FIND_NODE":
			if msg.Target == nil{
				return nil 
			}
			kClosest := kad.RoutingTable.FindClosestContacts(msg.Target, K)
			return &RPCMessage{
				Type:							"FIND_NODE_REPLY",
				TransactionID:		msg.TransactionID,
				Sender:						kad.Me,
				Contacts:					kClosest,
			}
		default:
			log.Printf("Unknown RPC type recieved: %s", msg.Type)
			return nil 
	}
}


func (kad *Kademlia) SendPing(targetContact *Contact) (*RPCMessage, error){
	return kad.Network.SendPingMessage(kad.Me, targetContact)
}

func (kademlia *Kademlia) LookupContact(target *Contact) []Contact{
	
	// Create the shortlist
	shortlist := ContactCandidates{
		contacts: kademlia.RoutingTable.FindClosestContacts(target.ID, K),
	}

	// Track IDs of contacts that have already been probed 
	contacted := make(map[string]bool)

	for {

		// select Alpha uncontacted candidates from shortlist 
		var candidatesToContact []Contact
		for _, c := range shortlist.contacts {
			if !contacted[c.ID.String()]{ // contact not in contacted
					candidatesToContact = append(candidatesToContact, c)	
					contacted[c.ID.String()] = true 
				if len(candidatesToContact) == Alpha{
					break
				}
			}
		}

		// no more contacts to be probed this round
		if len(candidatesToContact) == 0{
			break
		}

		
		// variables for concurrent probing 
		var wg sync.WaitGroup
		var mu sync.Mutex 
		var newContacts []Contact 
		
		// Concurrently FIND_NODE probe with goroutine 
		for _, contact := range candidatesToContact{
			wg.Add(1)
			go func(c Contact){
				defer wg.Done()
				log.Printf("Probing...")
				resp, err := kademlia.Network.SendFindContactMessage(kademlia.Me, &c, target.ID)
				log.Printf("Received %d contacts from %s", len(resp.Contacts), contact.Address)
				if err != nil || resp == nil{
					return
				}
				
				// Must lock to prevent race cond.
				mu.Lock()
				for _, neighbor := range resp.Contacts{
					neighbor.CalcDistance(target.ID)
					newContacts = append(newContacts, neighbor)
				}
				mu.Unlock()
			}(contact)
		}

		wg.Wait()
		

		// Check that new contacts are not self or already in shortlist
		var existingContacts = make(map[string]bool)
		for _, c := range shortlist.contacts{
			existingContacts[c.ID.String()] = true
		}
		
		var newUniqueContacts []Contact
		for _, c := range newContacts {
			if c.ID != nil &&!c.ID.Equals(kademlia.Me.ID) && !existingContacts[c.ID.String()]{
				newUniqueContacts = append(newUniqueContacts, c)
				existingContacts[c.ID.String()] = true
			}
		}

		// Add new unique contacts, re-sort, and trim to K  
		if len(newUniqueContacts) > 0 {
			shortlist.Append(newUniqueContacts)
			shortlist.Sort()
			if shortlist.Len() > K {
				shortlist.contacts = shortlist.GetContacts(K)
			}
		}

		// Assure that all top-K contacts in shortlist have been contacted 
		allTopKContacted := true 
		for _, c := range shortlist.contacts {
			if !contacted[c.ID.String()] {
				allTopKContacted = false 
				break 
			}
		}

		if allTopKContacted {
			break 
		}

	}

	// return at most k contacts 
	limit := K 
	if shortlist.Len() < limit {
		limit = shortlist.Len()
	}
	return shortlist.GetContacts(limit)
		
}

func (kademlia *Kademlia) LookupData(hash string) {
	// TODO
}

func (kademlia *Kademlia) Store(data []byte) {
	// TODO
}
