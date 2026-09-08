package kademlia

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Go udp references:
// https://pkg.go.dev/net
// https://dev.to/jones_charles_ad50858dbc0/go-udp-programming-a-beginner-friendly-guide-to-building-fast-real-time-apps-4ik

type Network struct {
	me      Contact
	conn    *net.UDPConn
	mu      sync.Mutex
	pending map[uuid.UUID]chan RPCMessage
}

func NewUDPNewtork(me Contact) *Network {
	return &Network{
		me:      me,
		pending: make(map[uuid.UUID]chan RPCMessage),
	}
}

func (n *Network) Listen(ip string, port int) error {
	// Setup up UDP address
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	n.conn = conn

	go n.listenLoop()
	return nil
}

func (n *Network) SendPingMessage(contact *Contact) (*RPCMessage, error) {
	req := RPCMessage{
		Type:          Ping,
		TransactionID: uuid.New(),
		Sender:        n.me,
	}

	res, err := n.sendRPC(contact.Address, req, 1*time.Second)
	if err != nil {
		return nil, err
	}

	return &res, nil
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
func (n *Network) listenLoop() {
	// Incoming data
	buf := make([]byte, 65535) // Max UDP packet size

	for {
		// Read client message
		bytesRead, raddr, err := n.conn.ReadFromUDP(buf)
		if err != nil {
			slog.Error("failed read from udp conn", slog.Any("err", err))
			return // Probably connection closed
		}

		var msg RPCMessage
		if err := json.Unmarshal(buf[:bytesRead], &msg); err != nil {
			slog.Error("failed to deserialize udp packet", slog.Any("err", err))
			continue
		}

		n.handleMessage(msg, raddr)
	}
}

// handleMessage evaluates if the incoming packet is related to an existing
// request (through the transaction ID) or if it's a new request
func (n *Network) handleMessage(msg RPCMessage, raddr *net.UDPAddr) {
	// Check if it's a response to one of the pending requests
	n.mu.Lock()
	ch, exists := n.pending[msg.TransactionID]
	n.mu.Unlock()

	if exists {
		ch <- msg
		return
	}

	// New request
	switch msg.Type {
	case Ping:
		// Reply with pong using the same transaction id
		reply := RPCMessage{
			Type:          Pong,
			TransactionID: msg.TransactionID,
			Sender:        n.me,
		}

		data, _ := json.Marshal(reply)
		// Currently ignoring error as package loss atm -> TODO handle it
		n.conn.WriteToUDP(data, raddr)
	}
}

func (n *Network) sendRPC(receiverAddr string, req RPCMessage, timeout time.Duration) (RPCMessage, error) {
	// Connect to server/node
	raddr, err := net.ResolveUDPAddr("udp", receiverAddr)
	if err != nil {
		return RPCMessage{}, err
	}

	// Create a response channel for the transaction
	resChan := make(chan RPCMessage, 1)

	n.mu.Lock()
	n.pending[req.TransactionID] = resChan
	n.mu.Unlock()

	// Clean up when done
	defer func() {
		n.mu.Lock()
		delete(n.pending, req.TransactionID)
		n.mu.Unlock()
	}()

	// Serialize and send
	data, err := json.Marshal(req)
	if err != nil {
		return RPCMessage{}, err
	}

	if _, err := n.conn.WriteToUDP(data, raddr); err != nil {
		return RPCMessage{}, err
	}

	// Wait for response or timeout
	select {
	case res := <-resChan:
		return res, nil
	case <-time.After(timeout):
		return RPCMessage{}, fmt.Errorf("rpc timed out after %v", timeout)
	}
}

type RPCType string

const (
	Ping        RPCType = "PING"
	Pong        RPCType = "PONG"
	FindContact RPCType = "FIND_CONTACT"
	FindData    RPCType = "FIND_DATA"
	Store       RPCType = "STORE"
)

// RPC responses must be unambiguously matched to the corresponding request.
// In addition, an attacker who cannot observe the request must not be able
// to forge a plausible response. (Might need help from Carl's lecture)
type RPCMessage struct {
	TransactionID uuid.UUID   `json:"transaction_id"`
	Type          RPCType     `json:"type"`
	Sender        Contact     `json:"sender"`
	Receiver      Contact     `json:"receiver"`
	TargetID      *KademliaID `json:"target_id,omitempty"`
	Contacts      []Contact   `json:"contacts,omitempty"`
	Data          []byte      `json:"data,omitempty"`
	//network  Network // Reference to network for replies
}
