package kademlia

import (
	"log"
)

type Kademlia struct {
	Me						Contact
	RoutingTable	*RoutingTable
	Network				*Network
}

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
				Type: "PONG",
				TransactionID: msg.TransactionID,
				Sender: kad.Me, 
			} 
		default:
			log.Printf("Unknown RPC type recieved: %s", msg.Type)
			return nil 
	}
}

func (kad *Kademlia) SendPing(targetContact *Contact) (*RPCMessage, error){
	return kad.Network.SendPingMessage(kad.Me, targetContact)
}

func (kademlia *Kademlia) LookupContact(target *Contact) {
	// TODO
}

func (kademlia *Kademlia) LookupData(hash string) {
	// TODO
}

func (kademlia *Kademlia) Store(data []byte) {
	// TODO
}
