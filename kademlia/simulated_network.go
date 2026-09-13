package kademlia

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// SimulatedHub represents an in-memory network connecting simulated Kademlia nodes.
// It supports configurable packet loss, artificial latency, and metrics collection
// for experiments and high-performance in-process testing.
type SimulatedHub struct {
	mu               sync.RWMutex
	nodes            map[string]*SimulatedNetwork
	packetLoss       float64 // 0.0 to 1.0
	latency          time.Duration
	rng              *rand.Rand
	rngMu            sync.Mutex
	totalProbes      atomic.Int64
	successfulProbes atomic.Int64
	droppedProbes    atomic.Int64
}

// NewSimulatedHub creates a new SimulatedHub with an optional seed for reproducible runs.
func NewSimulatedHub(seed ...int64) *SimulatedHub {
	var s int64 = time.Now().UnixNano()
	if len(seed) > 0 {
		s = seed[0]
	}
	return &SimulatedHub{
		nodes: make(map[string]*SimulatedNetwork),
		rng:   rand.New(rand.NewSource(s)),
	}
}

// SetPacketLoss sets the drop probability (0.0 <= loss <= 1.0).
func (h *SimulatedHub) SetPacketLoss(loss float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if loss < 0 {
		loss = 0
	} else if loss > 1.0 {
		loss = 1.0
	}
	h.packetLoss = loss
}

// SetLatency sets artificial network delay per RPC.
func (h *SimulatedHub) SetLatency(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.latency = d
}

// Register adds a node's simulated network to the hub.
func (h *SimulatedHub) Register(net *SimulatedNetwork) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nodes[net.me.Address] = net
}

// Unregister removes a node's simulated network from the hub.
func (h *SimulatedHub) Unregister(address string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.nodes, address)
}

// TotalProbes returns the total count of probes dispatched through this hub.
func (h *SimulatedHub) TotalProbes() int64 {
	return h.totalProbes.Load()
}

// SuccessfulProbes returns the count of probes that reached their destination without loss.
func (h *SimulatedHub) SuccessfulProbes() int64 {
	return h.successfulProbes.Load()
}

// DroppedProbes returns the count of probes dropped due to simulated packet loss or unreachability.
func (h *SimulatedHub) DroppedProbes() int64 {
	return h.droppedProbes.Load()
}

// ResetMetrics resets probe counters to zero.
func (h *SimulatedHub) ResetMetrics() {
	h.totalProbes.Store(0)
	h.successfulProbes.Store(0)
	h.droppedProbes.Store(0)
}

// SimulatedNetwork implements Network interface for in-memory simulated and mock testing.
type SimulatedNetwork struct {
	me  Contact
	rt  *RoutingTable
	hub *SimulatedHub
}

// NewSimulatedNetwork creates a new SimulatedNetwork and registers it with the hub.
func NewSimulatedNetwork(me Contact, rt *RoutingTable, hub *SimulatedHub) *SimulatedNetwork {
	sn := &SimulatedNetwork{
		me:  me,
		rt:  rt,
		hub: hub,
	}
	if hub != nil {
		hub.Register(sn)
	}
	return sn
}

// Close unregisters the node from the hub.
func (n *SimulatedNetwork) Close() error {
	if n.hub != nil {
		n.hub.Unregister(n.me.Address)
	}
	return nil
}

// SendPingMessage sends an in-memory PING to the target contact.
func (n *SimulatedNetwork) SendPingMessage(contact *Contact) (*RPCMessage, error) {
	if contact == nil || contact.ID == nil {
		return nil, fmt.Errorf("cannot ping nil contact")
	}
	if n.hub == nil {
		return nil, fmt.Errorf("simulated network hub is nil")
	}

	n.hub.totalProbes.Add(1)

	n.hub.mu.RLock()
	targetNet, exists := n.hub.nodes[contact.Address]
	loss := n.hub.packetLoss
	latency := n.hub.latency
	n.hub.mu.RUnlock()

	if latency > 0 {
		time.Sleep(latency)
	}

	if loss > 0 {
		n.hub.rngMu.Lock()
		roll := n.hub.rng.Float64()
		n.hub.rngMu.Unlock()
		if roll < loss {
			n.hub.droppedProbes.Add(1)
			return nil, fmt.Errorf("simulated network timeout (packet loss)")
		}
	}

	if !exists || targetNet == nil {
		n.hub.droppedProbes.Add(1)
		return nil, fmt.Errorf("node %s unreachable", contact.Address)
	}

	n.hub.successfulProbes.Add(1)

	// Target updates its routing table with sender
	if targetNet.rt != nil && n.me.ID != nil {
		if targetNet.me.ID == nil || !n.me.ID.Equals(targetNet.me.ID) {
			targetNet.rt.AddContact(n.me)
		}
	}

	// Sender updates its routing table with target
	if n.rt != nil && targetNet.me.ID != nil {
		if n.me.ID == nil || !targetNet.me.ID.Equals(n.me.ID) {
			n.rt.AddContact(targetNet.me)
		}
	}

	reply := &RPCMessage{
		Type:          Pong,
		TransactionID: uuid.New(),
		Sender:        targetNet.me,
		Receiver:      n.me,
	}
	return reply, nil
}

// SendFindContactMessage sends an in-memory FIND_CONTACT to the target contact.
func (n *SimulatedNetwork) SendFindContactMessage(target *KademliaID, contact *Contact) ([]Contact, error) {
	if contact == nil || contact.ID == nil {
		return nil, fmt.Errorf("cannot query nil contact")
	}
	if target == nil {
		return nil, fmt.Errorf("cannot query nil target ID")
	}
	if n.hub == nil {
		return nil, fmt.Errorf("simulated network hub is nil")
	}

	n.hub.totalProbes.Add(1)

	n.hub.mu.RLock()
	targetNet, exists := n.hub.nodes[contact.Address]
	loss := n.hub.packetLoss
	latency := n.hub.latency
	n.hub.mu.RUnlock()

	if latency > 0 {
		time.Sleep(latency)
	}

	if loss > 0 {
		n.hub.rngMu.Lock()
		roll := n.hub.rng.Float64()
		n.hub.rngMu.Unlock()
		if roll < loss {
			n.hub.droppedProbes.Add(1)
			return nil, fmt.Errorf("simulated network timeout (packet loss)")
		}
	}

	if !exists || targetNet == nil {
		n.hub.droppedProbes.Add(1)
		return nil, fmt.Errorf("node %s unreachable", contact.Address)
	}

	n.hub.successfulProbes.Add(1)

	// Target updates its routing table with sender
	if targetNet.rt != nil && n.me.ID != nil {
		if targetNet.me.ID == nil || !n.me.ID.Equals(targetNet.me.ID) {
			targetNet.rt.AddContact(n.me)
		}
	}

	// Target finds closest contacts
	var filtered []Contact
	if targetNet.rt != nil {
		closest := targetNet.rt.FindClosestContacts(target, bucketSize)
		filtered = make([]Contact, 0, len(closest))
		for _, c := range closest {
			if c.ID == nil {
				continue
			}
			// Don't return the requester back to itself
			if n.me.ID != nil && c.ID.Equals(n.me.ID) {
				continue
			}
			// Don't return the target itself
			if targetNet.me.ID != nil && c.ID.Equals(targetNet.me.ID) {
				continue
			}
			filtered = append(filtered, c)
		}
	}

	return filtered, nil
}
