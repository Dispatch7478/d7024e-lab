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
	net1 := NewNetwork(kad1)
	if err := net1.Listen("127.0.0.1", 9001); err != nil {
		t.Fatalf("Failed to listen on 9001: %v", err)
	}
	defer net1.conn.Close()

	//setup node 2
	id2 := NewRandomKademliaID()
	c2 := NewContact(id2, "127.0.0.1:9002")
	kad2 := &Kademlia{Me: c2, RoutingTable: NewRoutingTable(c2)}
	net2 := NewNetwork(kad2)
	if err := net2.Listen("127.0.0.1", 9002); err != nil {
		t.Fatalf("Failed to listen on 9002: %v", err)
	}
	defer net2.conn.Close()

	//Node 1 sends PING to node 2
	resp, err := net1.SendPingMessage(&c2)
	if err != nil {
		t.Fatalf("Expected PONG, got %s", resp.Type)
	}
	fmt.Printf("Success! Recieved %s from %s\n", resp.Type, resp.Sender.Address)

}
