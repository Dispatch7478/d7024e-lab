package kademlia

import (
	"fmt"
	"testing"
)

func TestUDPCommunication(t *testing.T) {
	//Setup node 1
	id1 := NewRandomKademliaID()
	c1 := NewContact(id1, "127.0.0.1:9001")
	kad1 := &Kademlia{Me: c1, RoutingTable: NewRoutingTable(c1)}
	net1 := NewNetwork(kad1.HandleIncomingRPC)
	if err := net1.Listen("127.0.0.1", 9001); err != nil {
		t.Fatalf("Failed to listen on 9001: %v", err)
	}
	defer net1.conn.Close()

	//setup node 2
	id2 := NewRandomKademliaID()
	c2 := NewContact(id2, "127.0.0.1:9002")
	kad2 := &Kademlia{Me: c2, RoutingTable: NewRoutingTable(c2)}
	net2 := NewNetwork(kad2.HandleIncomingRPC)
	if err := net2.Listen("127.0.0.1", 9002); err != nil {
		t.Fatalf("Failed to listen on 9002: %v", err)
	}
	defer net2.conn.Close()

	//Node 1 sends PING to node 2
	resp, err := net1.SendPingMessage(kad1.Me, &c2 )
	if err != nil {
		t.Fatalf("Expected PONG, got %s", resp.Type)
	}
	fmt.Printf("Success! Recieved %s from %s\n", resp.Type, resp.Sender.Address)

}

// 1. Success Path
func TestSendFindContactMessage_Success(t *testing.T) {
	id1 := NewRandomKademliaID()
	c1 := NewContact(id1, "127.0.0.1:9101")
	kad1 := &Kademlia{Me: c1, RoutingTable: NewRoutingTable(c1)}
	net1 := NewNetwork(kad1.HandleIncomingRPC)
	kad1.Network = net1
	if err := net1.Listen("127.0.0.1", 9101); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer net1.Close()

	id2 := NewRandomKademliaID()
	c2 := NewContact(id2, "127.0.0.1:9102")
	kad2 := &Kademlia{Me: c2, RoutingTable: NewRoutingTable(c2)}
	net2 := NewNetwork(kad2.HandleIncomingRPC)
	kad2.Network = net2
	if err := net2.Listen("127.0.0.1", 9102); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer net2.Close()

	// Seed node 2 with a contact
	kad2.RoutingTable.AddContact(c1)

	// Send FIND_NODE
	targetID := NewRandomKademliaID()
	resp, err := net1.SendFindContactMessage(kad1.Me, &c2, targetID)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if resp == nil || resp.Type != "FIND_NODE_REPLY" {
		t.Fatalf("Expected FIND_NODE_REPLY, got: %v", resp)
	}
	if len(resp.Contacts) == 0 {
		t.Fatalf("Expected contacts in response, got 0")
	}
}

// 2. Invalid Target Address Error
func TestSendFindContactMessage_InvalidAddress(t *testing.T) {
	id1 := NewRandomKademliaID()
	c1 := NewContact(id1, "127.0.0.1:9103")
	net1 := NewNetwork(nil)
	if err := net1.Listen("127.0.0.1", 9103); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer net1.Close()

	// Invalid address format that fails net.ResolveUDPAddr
	invalidContact := NewContact(NewRandomKademliaID(), "999.999.999.999:invalid-port")

	resp, err := net1.SendFindContactMessage(c1, &invalidContact, id1)
	if err == nil {
		t.Fatalf("Expected address resolution error, got response: %v", resp)
	}
}

// 3. Timeout Error
func TestSendFindContactMessage_Timeout(t *testing.T) {
	id1 := NewRandomKademliaID()
	c1 := NewContact(id1, "127.0.0.1:9104")
	net1 := NewNetwork(nil)
	if err := net1.Listen("127.0.0.1", 9104); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer net1.Close()

	// Target address where no server is listening
	unresponsiveContact := NewContact(NewRandomKademliaID(), "127.0.0.1:9999")

	resp, err := net1.SendFindContactMessage(c1, &unresponsiveContact, id1)
	if err == nil {
		t.Fatalf("Expected timeout error, got response: %v", resp)
	}
}
