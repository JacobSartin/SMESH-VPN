package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"uuid"

	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

var (
	errInvalidPeerID      = errors.New("invalid peer id")
	errInvalidPeerAddress = errors.New("invalid peer address")
	errPeerNotFound       = errors.New("peer not found")
)

// PeerRecord is the discovery server's public view of a registered peer.
type PeerRecord struct {
	ID       uuid.UUID `json:"id"`
	Address  string    `json:"address"`
	LastSeen time.Time `json:"last_seen"`
}

type peerRegistrationRequest struct {
	ID      uuid.UUID `json:"id"`
	Address string    `json:"address"`
}

// DiscoveryServer coordinates peers by keeping a small in-memory registry.
type DiscoveryServer struct {
	manager *session.SessionManager
	ttl     time.Duration
	now     func() time.Time

	mu    sync.RWMutex
	peers map[uuid.UUID]PeerRecord
}

// NewDiscoveryServer creates an in-memory discovery server.
func NewDiscoveryServer(manager *session.SessionManager, ttl time.Duration) *DiscoveryServer {
	return &DiscoveryServer{
		manager: manager,
		ttl:     ttl,
		now:     time.Now,
		peers:   make(map[uuid.UUID]PeerRecord),
	}
}

// RegisterPeer adds or refreshes a peer in the registry.
func (ds *DiscoveryServer) RegisterPeer(id uuid.UUID, address string) (PeerRecord, error) {
	if id == uuid.Nil() {
		return PeerRecord{}, errInvalidPeerID
	}
	if strings.TrimSpace(address) == "" {
		return PeerRecord{}, errInvalidPeerAddress
	}

	record := PeerRecord{
		ID:       id,
		Address:  address,
		LastSeen: ds.now(),
	}

	ds.mu.Lock()
	ds.peers[id] = record
	ds.mu.Unlock()

	return record, nil
}

// GetPeer returns a peer by ID.
func (ds *DiscoveryServer) GetPeer(id uuid.UUID) (PeerRecord, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	record, exists := ds.peers[id]
	return record, exists
}

// ListPeers returns all non-expired peers except the optional excluded peer.
func (ds *DiscoveryServer) ListPeers(exclude uuid.UUID) []PeerRecord {
	ds.CleanupExpired()

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	peers := make([]PeerRecord, 0, len(ds.peers))
	for id, record := range ds.peers {
		if exclude != uuid.Nil() && id == exclude {
			continue
		}
		peers = append(peers, record)
	}

	sort.Slice(peers, func(i, j int) bool {
		return peers[i].ID.String() < peers[j].ID.String()
	})

	return peers
}

// RemovePeer removes a peer from the registry.
func (ds *DiscoveryServer) RemovePeer(id uuid.UUID) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.peers[id]; !exists {
		return false
	}

	delete(ds.peers, id)
	return true
}

// CleanupExpired removes peers that have not refreshed before the TTL.
func (ds *DiscoveryServer) CleanupExpired() {
	if ds.ttl <= 0 {
		return
	}

	cutoff := ds.now().Add(-ds.ttl)

	ds.mu.Lock()
	defer ds.mu.Unlock()

	for id, record := range ds.peers {
		if record.LastSeen.Before(cutoff) {
			delete(ds.peers, id)
		}
	}
}

// Handler returns the HTTP API for discovery coordination.
func (ds *DiscoveryServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/peers", ds.handlePeers)
	mux.HandleFunc("/peers/", ds.handlePeerByID)
	return mux
}

func (ds *DiscoveryServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ds.handleListPeers(w, r)
	case http.MethodPost:
		ds.handleRegisterPeer(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ds *DiscoveryServer) handleRegisterPeer(w http.ResponseWriter, r *http.Request) {
	var req peerRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid registration payload: %v", err), http.StatusBadRequest)
		return
	}

	record, err := ds.RegisterPeer(req.ID, req.Address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusCreated, record)
}

func (ds *DiscoveryServer) handleListPeers(w http.ResponseWriter, r *http.Request) {
	var exclude uuid.UUID
	if rawExclude := r.URL.Query().Get("exclude"); rawExclude != "" {
		parsed, err := uuid.Parse(rawExclude)
		if err != nil {
			http.Error(w, "invalid exclude peer id", http.StatusBadRequest)
			return
		}
		exclude = parsed
	}

	writeJSON(w, http.StatusOK, ds.ListPeers(exclude))
}

func (ds *DiscoveryServer) handlePeerByID(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, "/peers/"))
	if err != nil {
		http.Error(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		record, exists := ds.GetPeer(id)
		if !exists {
			http.Error(w, errPeerNotFound.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, record)
	// TODO - this is unsecured, should be protected
	case http.MethodDelete:
		if !ds.RemovePeer(id) {
			http.Error(w, errPeerNotFound.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
	}
}
