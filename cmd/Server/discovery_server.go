package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"uuid"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

var (
	errInvalidPeerID       = errors.New("invalid peer id")
	errInvalidPeerAddress  = errors.New("invalid peer address")
	errPeerNotFound        = errors.New("peer not found")
	errPeerUnauthenticated = errors.New("a valid client certificate is required")
)

// PeerRecord is the discovery server's public view of a registered peer.
type PeerRecord struct {
	ID       uuid.UUID      `json:"id"`
	Address  netip.AddrPort `json:"address"`
	LastSeen time.Time      `json:"last_seen"`
}

type peerRegistrationRequest struct {
	Address netip.AddrPort `json:"address"`
}

type peerIDContextKey struct{}

// DiscoveryServer coordinates peers by keeping a small in-memory registry.
type DiscoveryServer struct {
	manager *session.SessionManager
	ca      *certs.CertificateAuthority
	ttl     time.Duration
	now     func() time.Time

	mu    sync.RWMutex
	peers map[uuid.UUID]PeerRecord
}

// NewDiscoveryServer creates an in-memory discovery server.
func NewDiscoveryServer(manager *session.SessionManager, ca *certs.CertificateAuthority, ttl time.Duration) *DiscoveryServer {
	return &DiscoveryServer{
		manager: manager,
		ca:      ca,
		ttl:     ttl,
		now:     time.Now,
		peers:   make(map[uuid.UUID]PeerRecord),
	}
}

// RegisterPeer adds or refreshes the peer identified by its verified certificate.
func (ds *DiscoveryServer) RegisterPeer(id uuid.UUID, address netip.AddrPort) (PeerRecord, error) {
	if id == uuid.Nil() {
		return PeerRecord{}, errInvalidPeerID
	}
	if !address.IsValid() || address.Port() == 0 {
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
	ds.mu.Lock()
	defer ds.mu.Unlock()

	record, exists := ds.peers[id]
	if exists && ds.expired(record) {
		delete(ds.peers, id)
		return PeerRecord{}, false
	}
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

// RemovePeer removes the peer identified by the authenticated request.
func (ds *DiscoveryServer) RemovePeer(id uuid.UUID) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	record, exists := ds.peers[id]
	if !exists || ds.expired(record) {
		delete(ds.peers, id)
		return errPeerNotFound
	}

	delete(ds.peers, id)
	return nil
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

func (ds *DiscoveryServer) expired(record PeerRecord) bool {
	return ds.ttl > 0 && record.LastSeen.Before(ds.now().Add(-ds.ttl))
}

// Handler returns the HTTP API for discovery coordination.
func (ds *DiscoveryServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/peers", ds.handlePeers)
	mux.HandleFunc("/peers/", ds.handlePeerByID)
	return ds.requireClientCertificate(mux)
}

func (ds *DiscoveryServer) requireClientCertificate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ds.ca == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, errPeerUnauthenticated.Error(), http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		valid, err := ds.ca.ValidateClientCertificate(cert)
		if err != nil || !valid {
			http.Error(w, errPeerUnauthenticated.Error(), http.StatusUnauthorized)
			return
		}
		id, err := certs.ClientIDFromCertificate(cert)
		if err != nil {
			http.Error(w, errPeerUnauthenticated.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerIDContextKey{}, id)))
	})
}

func (ds *DiscoveryServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ds.handleListPeers(w, r)
	case http.MethodPost:
		ds.handleRegisterPeer(w, r)
	case http.MethodDelete:
		ds.handleRemovePeer(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ds *DiscoveryServer) handleRemovePeer(w http.ResponseWriter, r *http.Request) {
	if err := ds.RemovePeer(authenticatedPeerID(r)); err != nil {
		if errors.Is(err, errPeerNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (ds *DiscoveryServer) handleRegisterPeer(w http.ResponseWriter, r *http.Request) {
	var req peerRegistrationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid registration payload: %v", err), http.StatusBadRequest)
		return
	}

	record, err := ds.RegisterPeer(authenticatedPeerID(r), req.Address)
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
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func authenticatedPeerID(r *http.Request) uuid.UUID {
	id, _ := r.Context().Value(peerIDContextKey{}).(uuid.UUID)
	return id
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
	}
}
