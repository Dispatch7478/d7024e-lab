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

type Network struct {
	conn     *net.UDPConn // net: package for portable interface for network I/O
	kademlia *Kademlia
	mu       sync.Mutex
	RPC      map[string]chan RPCMessage
}

type RPCMessage struct {
	Type          string      `json:"type"` // PING, PONG, etc.
	TransactionID string      `json:"tx_id"`
	Sender        Contact     `json:"sender"`
	Target        *KademliaID `json:"target, omitempty"`
	Contacts      []Contact   `json:"contacts, omitempty"`
}

func NewNetwork(kademlia *Kademlia) *Network {
	return &Network{
		kademlia: kademlia,
		RPC:      make(map[string]chan RPCMessage),
	}
}

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

func (network *Network) SendPingMessage(contact *Contact) (*RPCMessage, error) {
	// generate TransactionID
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	txID := hex.EncodeToString(b)

	respChan := make(chan RPCMessage, 1)

	network.mu.Lock()
	network.RPC[txID] = respChan
	network.mu.Unlock()

	defer func() {
		network.mu.Lock()
		delete(network.RPC, txID)
		network.mu.Unlock()
	}()

	msg := RPCMessage{
		Type:          "PING",
		TransactionID: txID,
		Sender:        network.kademlia.Me,
	}

	rAddr, err := net.ResolveUDPAddr("udp", contact.Address)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	_, err = network.conn.WriteToUDP(data, rAddr)
	if err != nil {
		return nil, err
	}

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
