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

type RPCType string

const (
	Ping             RPCType = "PING"
	Pong             RPCType = "PONG"
	FindContact      RPCType = "FIND_CONTACT"
	FindContactReply RPCType = "FIND_CONTACT_REPLY"
	FindData         RPCType = "FIND_DATA"
	FindDataReply    RPCType = "FIND_DATA_REPLY"
	Store            RPCType = "STORE"
	StoreReply       RPCType = "STORE_REPLY"
)

// RPC responses must be unambiguously matched to the corresponding request.
// In addition, an attacker who cannot observe the request must not be able
// to forge a plausible response -> uuid as tx id.
type RPCMessage struct {
	TransactionID uuid.UUID   `json:"transaction_id"`
	Type          RPCType     `json:"type"`
	Sender        Contact     `json:"sender"`
	Receiver      Contact     `json:"receiver"`
	TargetID      *KademliaID `json:"target_id,omitempty"`
	Contacts      []Contact   `json:"contacts,omitempty"`
	Data          []byte      `json:"data,omitempty"`
}

// Network defines the interface for Kademlia network communication.
// Both the real UDPNetwork and simulated/mock networks implement this interface.
type Network interface {
	SendPingMessage(contact *Contact) (*RPCMessage, error)
	SendFindContactMessage(target *KademliaID, contact *Contact) ([]Contact, error)
	SendFindDataMessage(target *KademliaID, contact *Contact) ([]byte, []Contact, error)
	SendStoreMessage(contact *Contact, key *KademliaID, data []byte) error
}

type UDPNetwork struct {
	me      Contact
	rt      *RoutingTable
	ds      *DataStore
	conn    *net.UDPConn
	mu      sync.Mutex
	pending map[uuid.UUID]chan RPCMessage
	timeout time.Duration
}

func NewUDPNetwork(me Contact, rt *RoutingTable, ds *DataStore) *UDPNetwork {
	return &UDPNetwork{
		me:      me,
		rt:      rt,
		ds:      ds,
		pending: make(map[uuid.UUID]chan RPCMessage),
	}
}

// SetTimeout sets a custom timeout for network RPC calls.
func (n *UDPNetwork) SetTimeout(d time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.timeout = d
}

func (n *UDPNetwork) Listen(ip string, port int) error {
	// Setup up UDP address
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	n.mu.Lock()
	n.conn = conn
	n.mu.Unlock()

	go n.listenLoop()
	return nil
}

// Close closes the UDP socket
func (n *UDPNetwork) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn != nil {
		return n.conn.Close()
	}
	return nil
}

func (n *UDPNetwork) SendPingMessage(contact *Contact) (*RPCMessage, error) {
	req := RPCMessage{
		Type:          Ping,
		TransactionID: uuid.New(),
		Sender:        n.me,
	}

	timeout := 1 * time.Second
	n.mu.Lock()
	if n.timeout > 0 {
		timeout = n.timeout
	}
	n.mu.Unlock()

	res, err := n.sendRPC(contact.Address, req, timeout)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (n *UDPNetwork) SendFindContactMessage(target *KademliaID, contact *Contact) ([]Contact, error) {
	req := RPCMessage{
		Type:          FindContact,
		TransactionID: uuid.New(),
		Sender:        n.me,
		TargetID:      target,
	}

	timeout := 1 * time.Second
	n.mu.Lock()
	if n.timeout > 0 {
		timeout = n.timeout
	}
	n.mu.Unlock()

	res, err := n.sendRPC(contact.Address, req, timeout)
	if err != nil {
		return nil, err
	}
	return res.Contacts, nil
}

// SendFindDataMessage sends a FIND_DATA RPC to contact looking for target.
// Returns (data, nil, nil) if contact has the data.
// Returns (nil, contacts, nil) if contact returns closest contacts.
// Returns (nil, nil, err) if RPC fails or times out.
func (n *UDPNetwork) SendFindDataMessage(target *KademliaID, contact *Contact) ([]byte, []Contact, error) {
	if contact == nil || contact.ID == nil {
		return nil, nil, fmt.Errorf("cannot query nil contact")
	}
	if target == nil {
		return nil, nil, fmt.Errorf("target ID cannot be nil")
	}

	req := RPCMessage{
		Type:          FindData,
		TransactionID: uuid.New(),
		Sender:        n.me,
		TargetID:      target,
	}

	timeout := 1 * time.Second
	n.mu.Lock()
	if n.timeout > 0 {
		timeout = n.timeout
	}
	n.mu.Unlock()

	res, err := n.sendRPC(contact.Address, req, timeout)
	if err != nil {
		return nil, nil, err
	}

	if len(res.Data) > 0 {
		return res.Data, nil, nil
	}
	return nil, res.Contacts, nil
}

// SendStoreMessage sends a STORE RPC to contact to store key and data.
func (n *UDPNetwork) SendStoreMessage(contact *Contact, key *KademliaID, data []byte) error {
	if contact == nil || contact.ID == nil {
		return fmt.Errorf("cannot store to nil contact")
	}
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}

	req := RPCMessage{
		Type:          Store,
		TransactionID: uuid.New(),
		Sender:        n.me,
		TargetID:      key,
		Data:          data,
	}

	timeout := 1 * time.Second
	n.mu.Lock()
	if n.timeout > 0 {
		timeout = n.timeout
	}
	n.mu.Unlock()

	_, err := n.sendRPC(contact.Address, req, timeout)
	return err
}

// ==================HELPERS==========================

// updateRoutingTable adds contact c to the local routing table if valid and not self.
func (n *UDPNetwork) updateRoutingTable(c Contact) {
	if n.rt == nil || c.ID == nil {
		return
	}
	if n.me.ID != nil && c.ID.Equals(n.me.ID) {
		return
	}
	n.rt.AddContact(c)
}

func (n *UDPNetwork) listenLoop() {
	// Incoming data buffer
	buf := make([]byte, 65535) // Max UDP packet size

	for {
		// Blocks unti the packet/datagram arrives
		len, raddr, err := n.conn.ReadFromUDP(buf)
		if err != nil {
			slog.Error("failed read from udp conn", "err", err)
			return
		}

		var msg RPCMessage
		err = json.Unmarshal(buf[:len], &msg)
		if err != nil {
			slog.Error("failed to deserialize udp packet", "err", err)
			continue
		}

		// Dispatch each message asynchronously so packet handling does not block the read loop.
		go n.handleMessage(msg, raddr)
	}
}

// handleMessage evaluates if the incoming packet is related to an existing
// request (through the transaction ID) or if it's a new request
func (n *UDPNetwork) handleMessage(msg RPCMessage, raddr *net.UDPAddr) {
	// In Kademlia, every received packet (request or reply) refreshes the sender in our routing table
	n.updateRoutingTable(msg.Sender)

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
	case FindContact:
		var filtered []Contact
		if n.rt != nil {
			closest := n.rt.FindClosestContacts(msg.TargetID, bucketSize)
			filtered = make([]Contact, 0, len(closest))
			for _, c := range closest {
				if msg.Sender.ID != nil && c.ID != nil && c.ID.Equals(msg.Sender.ID) {
					continue
				}
				if n.me.ID != nil && c.ID != nil && c.ID.Equals(n.me.ID) {
					continue
				}
				filtered = append(filtered, c)
			}
		}

		reply := RPCMessage{
			Type:          FindContact,
			TransactionID: msg.TransactionID,
			Sender:        n.me,
			Contacts:      filtered,
		}

		data, _ := json.Marshal(reply)
		n.conn.WriteToUDP(data, raddr)

	case FindData:
		reply := RPCMessage{
			Type:          FindDataReply,
			TransactionID: msg.TransactionID,
			Sender:        n.me,
		}

		var val []byte
		var found bool
		if n.ds != nil && msg.TargetID != nil {
			val, found = n.ds.Get(*msg.TargetID)
		}

		if found {
			reply.Data = val
		} else if n.rt != nil && msg.TargetID != nil {
			closest := n.rt.FindClosestContacts(msg.TargetID, bucketSize)
			filtered := make([]Contact, 0, len(closest))
			for _, c := range closest {
				if msg.Sender.ID != nil && c.ID != nil && c.ID.Equals(msg.Sender.ID) {
					continue
				}
				if n.me.ID != nil && c.ID != nil && c.ID.Equals(n.me.ID) {
					continue
				}
				filtered = append(filtered, c)
			}
			reply.Contacts = filtered
		}

		data, _ := json.Marshal(reply)
		n.conn.WriteToUDP(data, raddr)

	case Store:
		if n.ds != nil && msg.TargetID != nil && msg.Data != nil {
			if err := n.ds.Store(*msg.TargetID, msg.Data); err != nil {
				slog.Warn("rejected STORE request", "err", err, "key", msg.TargetID)
			}
		}

		reply := RPCMessage{
			Type:          StoreReply,
			TransactionID: msg.TransactionID,
			Sender:        n.me,
		}

		data, _ := json.Marshal(reply)
		n.conn.WriteToUDP(data, raddr)
	}
}

func (n *UDPNetwork) sendRPC(receiverAddr string, req RPCMessage, timeout time.Duration) (RPCMessage, error) {
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

	n.mu.Lock()
	conn := n.conn
	n.mu.Unlock()
	if conn == nil {
		return RPCMessage{}, fmt.Errorf("network is closed")
	}

	if _, err := conn.WriteToUDP(data, raddr); err != nil {
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
