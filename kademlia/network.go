package kademlia

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Network handles low-level UDP-socket communication and incoming RPC dispatching 
type Network struct {

	// conn is the active UDP socket listener. 
	conn     *net.UDPConn 
	
	// kademlia points to the local node to allow the network 
	// layer to update the routing table etc.
	kademlia *Kademlia

	//mu is a mutex lock.
	mu       sync.Mutex

	// RPC maps in-transmission Transaction IDs to their response channels.
	RPC      map[string]chan RPCMessage
}

// RPCMessage contains all transmission-critical information
type RPCMessage struct {
	// PING, PONG, etc.
	Type          string      `json:"type"`

	// Unique ID to distinguish between in-transmission messages 
	TransactionID string      `json:"tx_id"`

	// Sender of the message 
	Sender        Contact     `json:"sender"`

	// Target of the message
	Target        *KademliaID `json:"target, omitempty"`

	// A contact list 
	Contacts      []Contact   `json:"contacts, omitempty"`
}

// NewNetwork to create a new network instance 
func NewNetwork(kademlia *Kademlia) *Network {
	return &Network{
		kademlia: kademlia,
		RPC:      make(map[string]chan RPCMessage),
	}
}

// Listen binds a UDP socket to the specified IP and port, starting a background 
// listener loop to recieve and process incoming network packets.
func (network *Network) Listen(ip string, port int) error {

	// Set up UDP ip:port
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))

	if err != nil {
		log.Printf("could not resolve address: %v", err)
		return err
	}

	// Start listening
	conn, err := net.ListenUDP("udp", addr)

	if err != nil {
		log.Printf("Listen Failed: %v", err)
		return err
	}

	network.conn = conn

	go func() {

		buf := make([]byte, 65535)

		for {
			n, rAddr, err := network.conn.ReadFromUDP(buf)

			if err != nil {
				log.Printf("Read error %v", err)
				return
			}

			var msg RPCMessage
			if err := json.Unmarshal(buf[:n], &msg); err != nil {
				continue
			}

			// if RPC is response from our request
			network.mu.Lock()
			ch, exists := network.RPC[msg.TransactionID]
			network.mu.Unlock()

			if exists {
				ch <- msg
				continue
			}

			// handle as incoming request
			go network.handleRequest(msg, rAddr)
		}
	}()

	return nil
}

// handleRequest processes incoming RPC requests, updates the routing table 
// with the sender's contact info, and dispatches the appropriate reply.
func (network *Network) handleRequest(msg RPCMessage, from *net.UDPAddr) {
	// Update routing table with senders info
	if network.kademlia != nil && msg.Sender.ID != nil {
		network.kademlia.RoutingTable.AddContact(msg.Sender)
	}
	var reply *RPCMessage

	switch msg.Type {
	case "PING":
		reply = &RPCMessage{
			Type:          "PONG",
			TransactionID: msg.TransactionID,
			Sender:        network.kademlia.Me,
		}
	}

	if reply != nil {
		data, err := json.Marshal(reply)
		if err == nil {
			_, _ = network.conn.WriteToUDP(data, from)
		}
	}
}

// SendPingMessage transmits a PING RPC to the target contact and blocks until 
// a corresponding PONG is recieved or the request times out.
func (network *Network) SendPingMessage(contact *Contact) (*RPCMessage, error) {
	
	// generate TransactionID
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	txID := hex.EncodeToString(b)
	
	// Channel and link transaction ID
	respChan := make(chan RPCMessage, 1)

	network.mu.Lock()
	network.RPC[txID] = respChan
	network.mu.Unlock()

	// delete when done
	defer func() {
		network.mu.Lock()
		delete(network.RPC, txID)
		network.mu.Unlock()
	}()

	// create PING RPC message
	msg := RPCMessage{
		Type:          "PING",
		TransactionID: txID,
		Sender:        network.kademlia.Me,
	}

	// get target/remote address
	rAddr, err := net.ResolveUDPAddr("udp", contact.Address)
	if err != nil {
		return nil, err
	}

	// marshal the outgoing RPC PING
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// write message to channel 
	_, err = network.conn.WriteToUDP(data, rAddr)
	if err != nil {
		return nil, err
	}

	// either response or time out
	select {
	case resp := <-respChan:
		return &resp, nil
	case <-time.After(2 * time.Second):
		return nil, fmt.Errorf("ping to %s timed out", contact.Address)
	}
}

func (network *Network) SendFindContactMessage(contact *Contact) {
	// TODO
}

func (network *Network) SendFindDataMessage(hash string) {
	// TODO
}

func (network *Network) SendStoreMessage(data []byte) {
	// TODO
}
