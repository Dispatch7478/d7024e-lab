package kademlia

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestNetwork_Ping_Success(t *testing.T) {
	addrA := "127.0.0.1:9101"
	addrB := "127.0.0.1:9102"

	idA := NewKademliaIDFromAddress(addrA)
	idB := NewKademliaIDFromAddress(addrB)

	contactA := NewContact(idA, addrA)
	contactB := NewContact(idB, addrB)

	netA := NewUDPNewtork(contactA, nil)
	if err := netA.Listen("127.0.0.1", 9101); err != nil {
		t.Fatalf("failed to start listener A: %v", err)
	}
	defer netA.Close()

	netB := NewUDPNewtork(contactB, nil)
	if err := netB.Listen("127.0.0.1", 9102); err != nil {
		t.Fatalf("failed to start listener B: %v", err)
	}
	defer netB.Close()

	// Give listeners a split second to bind
	time.Sleep(20 * time.Millisecond)

	res, err := netA.SendPingMessage(&contactB)
	if err != nil {
		t.Fatalf("expected ping to succeed, got error: %v", err)
	}

	if res.Type != Pong {
		t.Errorf("expected response type %s, got %s", Pong, res.Type)
	}

	if res.Sender.Address != addrB {
		t.Errorf("expected sender address %s, got %s", addrB, res.Sender.Address)
	}
}

func TestNetwork_Ping_Timeout(t *testing.T) {
	addrA := "127.0.0.1:9103"
	idA := NewKademliaIDFromAddress(addrA)
	contactA := NewContact(idA, addrA)

	netA := NewUDPNewtork(contactA, nil)
	if err := netA.Listen("127.0.0.1", 9103); err != nil {
		t.Fatalf("failed to start listener A: %v", err)
	}
	defer netA.Close()

	// Unreachable target port
	deadContact := NewContact(NewKademliaIDFromAddress("127.0.0.1:9999"), "127.0.0.1:9999")

	_, err := netA.SendPingMessage(&deadContact)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}

	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected error to mention timed out, got: %v", err)
	}
}

func TestNetwork_Listen_Error(t *testing.T) {
	addr := "127.0.0.1:9104"
	c := NewContact(NewKademliaIDFromAddress(addr), addr)
	net1 := NewUDPNewtork(c, nil)

	if err := net1.Listen("127.0.0.1", 9104); err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer net1.Close()

	// Attempting to listen on the exact same port must fail
	net2 := NewUDPNewtork(c, nil)
	if err := net2.Listen("127.0.0.1", 9104); err == nil {
		defer net2.Close()
		t.Errorf("expected error listening on already bound port, got nil")
	}
}

func TestNetwork_MalformedPacket(t *testing.T) {
	addr := "127.0.0.1:9105"
	c := NewContact(NewKademliaIDFromAddress(addr), addr)
	netA := NewUDPNewtork(c, nil)

	if err := netA.Listen("127.0.0.1", 9105); err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer netA.Close()

	// Send raw garbage bytes directly over UDP
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("malformed non-json packet")); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Give listen loop time to handle and discard without crashing
	time.Sleep(20 * time.Millisecond)
}

func TestNetwork_FindContactMessage(t *testing.T) {
	addrA := "127.0.0.1:9110"
	addrB := "127.0.0.1:9111"

	contactA := NewContact(NewKademliaIDFromAddress(addrA), addrA)
	contactB := NewContact(NewKademliaIDFromAddress(addrB), addrB)

	rtA := NewRoutingTable(contactA)
	rtB := NewRoutingTable(contactB)

	// Add 3 known contacts into Node B's routing table
	c1 := NewContact(NewKademliaID("1000000000000000000000000000000000000000000000000000000000000000"), "127.0.0.1:8001")
	c2 := NewContact(NewKademliaID("2000000000000000000000000000000000000000000000000000000000000000"), "127.0.0.1:8002")
	c3 := NewContact(NewKademliaID("3000000000000000000000000000000000000000000000000000000000000000"), "127.0.0.1:8003")
	rtB.AddContact(c1)
	rtB.AddContact(c2)
	rtB.AddContact(c3)

	netA := NewUDPNewtork(contactA, rtA)
	netB := NewUDPNewtork(contactB, rtB)

	if err := netA.Listen("127.0.0.1", 9110); err != nil {
		t.Fatalf("failed to listen A: %v", err)
	}
	defer netA.Close()

	if err := netB.Listen("127.0.0.1", 9111); err != nil {
		t.Fatalf("failed to listen B: %v", err)
	}
	defer netB.Close()

	time.Sleep(20 * time.Millisecond)

	// Node A queries Node B for contacts close to target
	target := NewKademliaID("1000000000000000000000000000000000000000000000000000000000000000")
	contacts, err := netA.SendFindContactMessage(target, &contactB)
	if err != nil {
		t.Fatalf("expected SendFindContactMessage to succeed, got %v", err)
	}

	// Considering that it will also return A itself. Might need
	// to either add later 
	if len(contacts) != 4 {
		t.Errorf("expected 4 contacts returned from Node B, got %d, %v", len(contacts), contacts)
	}
}
