package kademlia

import (
	"sort"
	"sync"
)

// CandidateStatus represents the query state of a contact during iterative lookup.
type CandidateStatus int

const (
	StatusUnqueried    CandidateStatus = iota // Hasn't received RPC
	StatusQueried                             // Received RPC and answered back
	StatusUnresponsive                        // Timeout or error
)

// Candidate tracks a contact and its lookup query status.
type Candidate struct {
	Contact Contact
	Status  CandidateStatus
}

// Shortlist manages contacts discovered during an iterative lookup for target.
// Contacts are filtered against the local node (me), and ordered by their
// XOR distance to the lookup target.
type Shortlist struct {
	target     *KademliaID
	meID       *KademliaID
	candidates map[string]*Candidate // keyed by hex string of KademliaID
	mu         sync.RWMutex
}

// NewShortlist creates a new Shortlist for a given target and local node ID.
func NewShortlist(target *KademliaID, meID *KademliaID) *Shortlist {
	return &Shortlist{
		target:     target,
		meID:       meID,
		candidates: make(map[string]*Candidate),
	}
}

// Add appends new contacts to the shortlist, calculating their distance to target.
// Contacts that have a nil ID, match meID, or are already in the shortlist are skipped.
func (s *Shortlist) Add(contacts ...Contact) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range contacts {
		if c.ID == nil {
			continue
		}
		if s.meID != nil && c.ID.Equals(s.meID) {
			continue
		}
		key := c.ID.String()
		if _, exists := s.candidates[key]; exists {
			continue // Already in shortlist; do not overwrite query status
		}
		c.CalcDistance(s.target)
		s.candidates[key] = &Candidate{
			Contact: c,
			Status:  StatusUnqueried,
		}
	}
}

// MarkQueried marks a contact as successfully queried.
func (s *Shortlist) MarkQueried(id *KademliaID) {
	if id == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if cand, exists := s.candidates[id.String()]; exists {
		cand.Status = StatusQueried
	}
}

// MarkUnresponsive marks a contact as unresponsive (e.g. timed out or network error).
func (s *Shortlist) MarkUnresponsive(id *KademliaID) {
	if id == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if cand, exists := s.candidates[id.String()]; exists {
		cand.Status = StatusUnresponsive
	}
}

// GetActiveCandidates returns all queried and unqueried candidates sorted by XOR distance to target.
func (s *Shortlist) GetActiveCandidates() []*Candidate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var active []*Candidate
	for _, cand := range s.candidates {
		if cand.Status != StatusUnresponsive {
			active = append(active, cand)
		}
	}

	sort.Slice(active, func(i, j int) bool {
		return active[i].Contact.Less(&active[j].Contact)
	})

	return active
}

// GetClosestUnqueried returns up to count (alpha) unqueried contacts among the
// closest withinK (or less) active candidates.
func (s *Shortlist) GetClosestUnqueried(count int, withinK int) []Contact {
	active := s.GetActiveCandidates()
	limit := min(withinK, len(active))

	var result []Contact
	for i := 0; i < limit && len(result) < count; i++ {
		if active[i].Status == StatusUnqueried {
			result = append(result, active[i].Contact)
		}
	}
	return result
}

// HasUnqueriedInTopK returns true if any of the closest k active candidates are unqueried.
// Used as the loop termination condition.
func (s *Shortlist) HasUnqueriedInTopK(k int) bool {
	active := s.GetActiveCandidates()
	limit := min(k, len(active))

	for i := 0; i < limit; i++ {
		if active[i].Status == StatusUnqueried {
			return true
		}
	}
	return false
}

// GetClosestQueried returns up to k queried contacts sorted by distance to target.
func (s *Shortlist) GetClosestQueried(k int) []Contact {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var queried []*Candidate
	for _, cand := range s.candidates {
		if cand.Status == StatusQueried {
			queried = append(queried, cand)
		}
	}

	sort.Slice(queried, func(i, j int) bool {
		return queried[i].Contact.Less(&queried[j].Contact)
	})

	limit := min(k, len(queried))

	result := make([]Contact, limit)
	for i := 0; i < limit; i++ {
		result[i] = queried[i].Contact
	}
	return result
}

// getCandidate returns a candidate by ID and whether it exists in the shortlist.
// It's only for tests.
func (s *Shortlist) getCandidate(id *KademliaID) (*Candidate, bool) {
	if id == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	cand, exists := s.candidates[id.String()]
	return cand, exists
}

// Len returns the total number of candidates in the shortlist.
func (s *Shortlist) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.candidates)
}
