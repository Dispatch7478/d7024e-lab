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

	netA := NewUDPNewtork(contactA)
	if err := netA.Listen("127.0.0.1", 9101); err != nil {
		t.Fatalf("failed to start listener A: %v", err)
	}
	defer netA.Close()

	netB := NewUDPNewtork(contactB)
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

	netA := NewUDPNewtork(contactA)
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
	net1 := NewUDPNewtork(c)

	if err := net1.Listen("127.0.0.1", 9104); err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer net1.Close()

	// Attempting to listen on the exact same port must fail
	net2 := NewUDPNewtork(c)
	if err := net2.Listen("127.0.0.1", 9104); err == nil {
		defer net2.Close()
		t.Errorf("expected error listening on already bound port, got nil")
	}
}

func TestNetwork_MalformedPacket(t *testing.T) {
	addr := "127.0.0.1:9105"
	c := NewContact(NewKademliaIDFromAddress(addr), addr)
	netA := NewUDPNewtork(c)

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
