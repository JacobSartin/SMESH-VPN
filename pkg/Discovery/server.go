// Package discovery implements the coordination server peers register with and
// the client they use to talk to it. All requests are authenticated with
// mutual TLS; a peer's identity is the client ID in its certificate.
package discovery

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
)

var (
	errInvalidPeerID       = errors.New("invalid peer id")
	errInvalidPeerAddress  = errors.New("invalid peer address")
	errInvalidVPNIP        = errors.New("vpn_ip must be a unicast IPv4 address")
	errVPNIPInUse          = errors.New("vpn_ip is already registered to another peer")
	errPeerNotFound        = errors.New("peer not found")
	errPeerUnauthenticated = errors.New("a valid client certificate is required")
)

// PeerRecord is the discovery server's public view of a registered peer.
type PeerRecord struct {
	ID uuid.UUID `json:"id"`
	// Address is the endpoint other peers dial to reach this peer.
	Address netip.AddrPort `json:"address"`
	// VPNIP is the peer's address inside the overlay network.
	VPNIP    netip.Addr `json:"vpn_ip"`
	LastSeen time.Time  `json:"last_seen"`
}

// RegistrationRequest is the body of POST /peers. An unspecified Address host
// (for example 0.0.0.0:7777) is replaced with the request's source IP.
type RegistrationRequest struct {
	Address netip.AddrPort `json:"address"`
	VPNIP   netip.Addr     `json:"vpn_ip"`
}

type peerIDContextKey struct{}

// Server coordinates peers by keeping a small in-memory registry.
type Server struct {
	ca  *certs.CertificateAuthority
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	peers map[uuid.UUID]PeerRecord
}

// NewServer creates an in-memory discovery server. Peers that do not refresh
// their registration within ttl are dropped.
func NewServer(ca *certs.CertificateAuthority, ttl time.Duration) *Server {
	return &Server{
		ca:    ca,
		ttl:   ttl,
		now:   time.Now,
		peers: make(map[uuid.UUID]PeerRecord),
	}
}

// RegisterPeer adds or refreshes the peer identified by its verified certificate.
func (ds *Server) RegisterPeer(id uuid.UUID, address netip.AddrPort, vpnIP netip.Addr) (PeerRecord, error) {
	if id == uuid.Nil() {
		return PeerRecord{}, errInvalidPeerID
	}
	if !address.IsValid() || address.Port() == 0 || address.Addr().IsUnspecified() {
		return PeerRecord{}, errInvalidPeerAddress
	}
	vpnIP = vpnIP.Unmap()
	if !vpnIP.Is4() || vpnIP.IsUnspecified() || vpnIP.IsMulticast() || vpnIP.IsLoopback() {
		return PeerRecord{}, errInvalidVPNIP
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.cleanupExpiredLocked()
	for otherID, other := range ds.peers {
		if otherID != id && other.VPNIP == vpnIP {
			return PeerRecord{}, errVPNIPInUse
		}
	}

	record := PeerRecord{
		ID:       id,
		Address:  address,
		VPNIP:    vpnIP,
		LastSeen: ds.now(),
	}
	ds.peers[id] = record
	return record, nil
}

// GetPeer returns a peer by ID.
func (ds *Server) GetPeer(id uuid.UUID) (PeerRecord, bool) {
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
func (ds *Server) ListPeers(exclude uuid.UUID) []PeerRecord {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.cleanupExpiredLocked()
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
func (ds *Server) RemovePeer(id uuid.UUID) error {
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
func (ds *Server) CleanupExpired() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.cleanupExpiredLocked()
}

func (ds *Server) cleanupExpiredLocked() {
	for id, record := range ds.peers {
		if ds.expired(record) {
			delete(ds.peers, id)
		}
	}
}

func (ds *Server) expired(record PeerRecord) bool {
	return ds.ttl > 0 && record.LastSeen.Before(ds.now().Add(-ds.ttl))
}

// Handler returns the HTTP API for discovery coordination:
//
//	POST   /peers       register or refresh the caller
//	GET    /peers       list live peers other than the caller
//	DELETE /peers       deregister the caller
//	GET    /peers/{id}  look up one peer
func (ds *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/peers", ds.handlePeers)
	mux.HandleFunc("/peers/", ds.handlePeerByID)
	return ds.requireClientCertificate(mux)
}

func (ds *Server) requireClientCertificate(next http.Handler) http.Handler {
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

func (ds *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, ds.ListPeers(authenticatedPeerID(r)))
	case http.MethodPost:
		ds.handleRegisterPeer(w, r)
	case http.MethodDelete:
		ds.handleRemovePeer(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ds *Server) handleRemovePeer(w http.ResponseWriter, r *http.Request) {
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

func (ds *Server) handleRegisterPeer(w http.ResponseWriter, r *http.Request) {
	var req RegistrationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid registration payload: %v", err), http.StatusBadRequest)
		return
	}

	address := req.Address
	if address.IsValid() && address.Addr().IsUnspecified() {
		source, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "cannot determine source address", http.StatusBadRequest)
			return
		}
		address = netip.AddrPortFrom(source.Addr().Unmap(), address.Port())
	}

	record, err := ds.RegisterPeer(authenticatedPeerID(r), address, req.VPNIP)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errVPNIPInUse) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}

	writeJSON(w, http.StatusOK, record)
}

func (ds *Server) handlePeerByID(w http.ResponseWriter, r *http.Request) {
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
	_ = json.NewEncoder(w).Encode(value)
}
