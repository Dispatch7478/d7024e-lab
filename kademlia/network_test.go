package kademlia

import (
	"d7024e/registry"
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

	netA := NewUDPNetwork(contactA, nil, NewDataStore())
	if err := netA.Listen("127.0.0.1", 9101); err != nil {
		t.Fatalf("failed to start listener A: %v", err)
	}
	defer netA.Close()

	netB := NewUDPNetwork(contactB, nil, NewDataStore())
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

	netA := NewUDPNetwork(contactA, nil, NewDataStore())
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
	net1 := NewUDPNetwork(c, nil, NewDataStore())

	if err := net1.Listen("127.0.0.1", 9104); err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer net1.Close()

	// Attempting to listen on the exact same port must fail
	net2 := NewUDPNetwork(c, nil, NewDataStore())
	if err := net2.Listen("127.0.0.1", 9104); err == nil {
		defer net2.Close()
		t.Errorf("expected error listening on already bound port, got nil")
	}
}

func TestNetwork_MalformedPacket(t *testing.T) {
	addr := "127.0.0.1:9105"
	c := NewContact(NewKademliaIDFromAddress(addr), addr)
	netA := NewUDPNetwork(c, nil, NewDataStore())

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

	netA := NewUDPNetwork(contactA, rtA, NewDataStore())
	netB := NewUDPNetwork(contactB, rtB, NewDataStore())

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

	// Node B had 3 contacts (c1, c2, c3). Node A was added to B's routing table,
	// but Node A must be filtered out so it is not returned back to itself.
	if len(contacts) != 3 {
		t.Errorf("expected 3 contacts returned from Node B, got %d, %v \n sender ID: %v", len(contacts), contacts, contactA)
	}
	for _, c := range contacts {
		if c.ID.Equals(contactA.ID) {
			t.Errorf("expected sender not to be returned in closest contacts, but got %v", c)
		}
	}
}

func TestNetwork_FindData_And_Store(t *testing.T) {
	addrA := "127.0.0.1:9120"
	addrB := "127.0.0.1:9121"

	contactA := NewContact(NewKademliaIDFromAddress(addrA), addrA)
	contactB := NewContact(NewKademliaIDFromAddress(addrB), addrB)

	dsA := NewDataStore()
	dsB := NewDataStore()
	netA := NewUDPNetwork(contactA, nil, dsA)
	netB := NewUDPNetwork(contactB, nil, dsB)

	if err := netA.Listen("127.0.0.1", 9120); err != nil {
		t.Fatalf("failed to listen A: %v", err)
	}
	defer netA.Close()

	if err := netB.Listen("127.0.0.1", 9121); err != nil {
		t.Fatalf("failed to listen B: %v", err)
	}
	defer netB.Close()

	time.Sleep(20 * time.Millisecond)

	val := []byte("udp payload package test data")
	key := NewKademliaIDFromData(val)

	// Node A sends STORE to Node B over UDP
	if err := netA.SendStoreMessage(&contactB, key, val); err != nil {
		t.Fatalf("expected SendStoreMessage to succeed over UDP, got %v", err)
	}

	// Give receiver goroutine time to process
	time.Sleep(20 * time.Millisecond)

	// Verify Node B stored it
	if !dsB.Has(*key) {
		t.Fatalf("expected node B to have stored the key in its DataStore")
	}

	// Node A queries Node B for existing data -> returns data
	foundData, closest, err := netA.SendFindDataMessage(key, &contactB)
	if err != nil {
		t.Fatalf("expected SendFindDataMessage to succeed, got %v", err)
	}
	if string(foundData) != string(val) {
		t.Errorf("expected %s, got %s", string(val), string(foundData))
	}
	if len(closest) != 0 {
		t.Errorf("expected empty contacts when data is found")
	}

	// Node A queries Node B for missing data -> returns contacts
	missingKey := NewKademliaID("9999999999999999999999999999999999999999999999999999999999999999")
	missingData, missingClosest, err := netA.SendFindDataMessage(missingKey, &contactB)
	if err != nil {
		t.Fatalf("expected SendFindDataMessage for missing key to succeed, got %v", err)
	}
	if len(missingData) != 0 {
		t.Errorf("expected empty data for missing key, got %s", string(missingData))
	}
	_ = missingClosest
}

func TestNetwork_LatestPointer_StoreAndReject(t *testing.T) {
	addrA := "127.0.0.1:9130"
	addrB := "127.0.0.1:9131"

	contactA := NewContact(NewKademliaIDFromAddress(addrA), addrA)
	contactB := NewContact(NewKademliaIDFromAddress(addrB), addrB)

	domain := "example.com"
	pkg := "udp-lp"
	dkpOwner, _ := registry.GenerateDomainKeyPair(domain)
	dkpAttacker, _ := registry.GenerateDomainKeyPair(domain)
	resolver := registry.NewMockDNSResolver()
	_ = resolver.SetKey(domain, dkpOwner.PublicKey)

	dsA := NewDataStore()
	dsB := NewDataStore()
	dsA.SetDNSResolver(resolver)
	dsB.SetDNSResolver(resolver)

	netA := NewUDPNetwork(contactA, nil, dsA)
	netB := NewUDPNetwork(contactB, nil, dsB)

	if err := netA.Listen("127.0.0.1", 9130); err != nil {
		t.Fatalf("failed to listen A: %v", err)
	}
	defer netA.Close()

	if err := netB.Listen("127.0.0.1", 9131); err != nil {
		t.Fatalf("failed to listen B: %v", err)
	}
	defer netB.Close()

	time.Sleep(20 * time.Millisecond)

	// Create v1.0.0 and v2.0.0
	_, _, vr1Bytes, vr1Hash, _, lp1Bytes, lpKey := createTestRelease(t, dkpOwner, pkg, "1.0.0", "b1", registry.ZeroHash)
	_, _, vr2Bytes, vr2Hash, _, lp2Bytes, _ := createTestRelease(t, dkpOwner, pkg, "2.0.0", "b2", vr1Hash)

	// Store VR1 and VR2 in Node B
	_ = dsB.Store(*NewKademliaID(vr1Hash), vr1Bytes)
	_ = dsB.Store(*NewKademliaID(vr2Hash), vr2Bytes)

	// Node A sends STORE for LP v2.0.0 to Node B over UDP
	if err := netA.SendStoreMessage(&contactB, &lpKey, lp2Bytes); err != nil {
		t.Fatalf("failed to send store LP over UDP: %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	// Verify Node B stored LP v2.0.0
	val, found := dsB.Get(lpKey)
	if !found {
		t.Fatalf("expected node B to have stored LP v2.0.0")
	}
	lpParsed, err := registry.ParseLatestPointer(val)
	if err != nil || lpParsed.Version != "2.0.0" {
		t.Fatalf("expected version 2.0.0, got: %v", lpParsed)
	}

	// Node A sends rollback STORE (v1.0.0) over UDP -> Node B must reject and retain v2.0.0!
	_ = netA.SendStoreMessage(&contactB, &lpKey, lp1Bytes)
	time.Sleep(30 * time.Millisecond)

	valAfterRollback, _ := dsB.Get(lpKey)
	lpParsedAfterRollback, _ := registry.ParseLatestPointer(valAfterRollback)
	if lpParsedAfterRollback.Version != "2.0.0" {
		t.Errorf("node B rolled back to %s after malicious UDP store!", lpParsedAfterRollback.Version)
	}

	// Node A sends forged LP signed with attacker key over UDP -> Node B must reject!
	_, _, vr3Bytes, vr3Hash, _, lp3ForgedBytes, _ := createTestRelease(t, dkpAttacker, pkg, "3.0.0", "b3", vr2Hash)
	_ = dsB.Store(*NewKademliaID(vr3Hash), vr3Bytes)
	_ = netA.SendStoreMessage(&contactB, &lpKey, lp3ForgedBytes)
	time.Sleep(30 * time.Millisecond)

	valAfterForged, _ := dsB.Get(lpKey)
	lpParsedAfterForged, _ := registry.ParseLatestPointer(valAfterForged)
	if lpParsedAfterForged.Version != "2.0.0" {
		t.Errorf("node B accepted forged LP version %s over UDP!", lpParsedAfterForged.Version)
	}
}
