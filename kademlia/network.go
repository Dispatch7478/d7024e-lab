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

// RPCHandler is a callback invoked when a incoming RPC message arrives 
type RPCHandler func(msg RPCMessage) *RPCMessage 

// Network handles low-level UDP-socket communication and incoming RPC dispatching 
type Network struct {

	// conn is the active UDP socket listener. 
	conn     				*net.UDPConn 
	
	// kademlia points to the local node to allow the network 
	// layer to update the routing table etc.
	handler 				RPCHandler

	//mu is a mutex lock.
	mu       				sync.Mutex

	// pendingRPC maps in-transmission Transaction IDs to their response channels.
	pendingRPC      map[string]chan RPCMessage
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
func NewNetwork(handler RPCHandler) *Network {
	return &Network{
		handler: 					handler,
		pendingRPC:				make(map[string]chan RPCMessage),
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

	go network.listenLoop()
	return nil
}

// Gracefully close the udp connection 
func (network *Network) Close() error {
	if network.conn != nil {
		return network.conn.Close()
	}
	return nil
}

func (network *Network) listenLoop() {
	buff := make([]byte, 65535)

	for {

		// Read from bytestream
		bytesRead, rAddr, err := network.conn.ReadFromUDP(buff)
		if err != nil {
			log.Printf("UDP read error: %w", err)
			return
		}

		// Unpakcage recieved message
		var msg RPCMessage
		if err := json.Unmarshal(buff[:bytesRead], &msg); err != nil{
			log.Printf("Unable to unmarshal packet from %s: %v", rAddr, err)
			continue
		}
		
		// Case 1: response to an active outgoing request
		network.mu.Lock()
		ch, exists := network.pendingRPC[msg.TransactionID]
		network.mu.Unlock()

		if exists {
			ch <- msg 
			continue
		}
		
		// case 2: treat as incoming request, pass on to handler
		if network.handler != nil {
			go func(req RPCMessage, senderAddr *net.UDPAddr){
				if reply := network.handler(req); reply != nil{
					data, err := json.Marshal(reply)
					if err == nil {
						_,_ = network.conn.WriteToUDP(data, senderAddr)
					}
				}
			}(msg, rAddr)
		}

	}
}

func (network *Network) sendRPC(targetAddr string, msg RPCMessage, timeout time.Duration) (*RPCMessage, error){

	rAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil{
		return nil, fmt.Errorf("Invalid target address %s: %w", targetAddr ,err)
	}
	
	// Channel and link transaction ID
	respChan := make(chan RPCMessage, 1)

	network.mu.Lock()
	network.pendingRPC[msg.TransactionID] = respChan
	network.mu.Unlock()

	// delete when done
	defer func() {
		network.mu.Lock()
		delete(network.pendingRPC, msg.TransactionID)
		network.mu.Unlock()
	}()

	// marshal the outgoing RPC PING
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// write message to channel 
	if _, err = network.conn.WriteToUDP(data, rAddr); err != nil{
		return nil, err
	}

	// either response or time out
	select {
	case resp := <-respChan:
		return &resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("RPC %s to %s timed out after %v", msg.Type, targetAddr, timeout)
	}
}

// generate a Transaction ID
func generateTxID() string{
	b := make([]byte, 16)
	_,_ =rand.Read(b)
	return hex.EncodeToString(b)
}

// SendPingMessage transmits a PING RPC to the target contact and blocks until 
// a corresponding PONG is recieved or the request times out.
func (network *Network) SendPingMessage(sender Contact, targetContact *Contact) (*RPCMessage, error) {
	msg := RPCMessage{
		Type: "PING",
		TransactionID: generateTxID(),
		Sender: sender,
	}	
	return network.sendRPC(targetContact.Address, msg, 2*time.Second)
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
