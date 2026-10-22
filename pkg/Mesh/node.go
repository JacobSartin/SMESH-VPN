// Package mesh connects a local TUN device to encrypted sessions with the
// peers listed by the discovery server.
package mesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
	"uuid"

	discovery "github.com/JacobSartin/SMESH-VPN/pkg/Discovery"
	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
	tun "github.com/JacobSartin/SMESH-VPN/pkg/Tun"
)

// PeerSource lists the other peers in the network. *discovery.Client implements it.
type PeerSource interface {
	ListPeers(ctx context.Context) ([]discovery.PeerRecord, error)
}

// Config configures a Node. Sessions, Peers, Listener, and Device are required.
type Config struct {
	// Sessions holds the local identity and the active sessions.
	Sessions *session.SessionManager
	// Peers is polled to learn peer endpoints and overlay addresses.
	Peers PeerSource
	// Listener accepts sessions from peers. Run closes it.
	Listener net.Listener
	// Device carries overlay packets. Run closes it.
	Device tun.Device

	// PollInterval is how often Peers is polled. Default 5s.
	PollInterval time.Duration
	// KeepaliveInterval is how often idle sessions send a keepalive. Default 10s.
	KeepaliveInterval time.Duration
	// MinBackoff and MaxBackoff bound the delay between failed dials to a peer. Defaults 1s and 30s.
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// Logf receives diagnostic messages. Default log.Printf.
	Logf func(format string, args ...any)
}

// Node runs the mesh for one local peer.
type Node struct {
	cfg  Config
	self uuid.UUID

	refresh chan struct{}

	mu      sync.Mutex
	peers   map[uuid.UUID]discovery.PeerRecord
	routes  map[netip.Addr]uuid.UUID
	dialing map[uuid.UUID]bool
	backoff map[uuid.UUID]dialBackoff
}

type dialBackoff struct {
	delay time.Duration
	next  time.Time
}

// New validates cfg and returns a Node ready to Run.
func New(cfg Config) (*Node, error) {
	if cfg.Sessions == nil || cfg.Peers == nil || cfg.Listener == nil || cfg.Device == nil {
		return nil, errors.New("mesh: Sessions, Peers, Listener, and Device are required")
	}
	identity := cfg.Sessions.Identity()
	if identity == nil || identity.ID == uuid.Nil() {
		return nil, errors.New("mesh: session manager has no identity")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.KeepaliveInterval <= 0 {
		cfg.KeepaliveInterval = 10 * time.Second
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = time.Second
	}
	if cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = max(30*time.Second, cfg.MinBackoff)
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}

	return &Node{
		cfg:     cfg,
		self:    identity.ID,
		refresh: make(chan struct{}, 1),
		peers:   make(map[uuid.UUID]discovery.PeerRecord),
		routes:  make(map[netip.Addr]uuid.UUID),
		dialing: make(map[uuid.UUID]bool),
		backoff: make(map[uuid.UUID]dialBackoff),
	}, nil
}

// Run serves until ctx is cancelled or the device or listener fails. It closes
// the listener, the device, and all sessions before returning.
func (n *Node) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 4)
	var wg sync.WaitGroup
	start := func(fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil && ctx.Err() == nil {
				errCh <- err
				cancel()
			}
		}()
	}
	start(n.acceptLoop)
	start(n.deviceLoop)
	start(n.pollLoop)
	start(n.keepaliveLoop)

	<-ctx.Done()
	n.cfg.Listener.Close()
	n.cfg.Device.Close()
	n.cfg.Sessions.CloseAll()
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// Route returns the peer that owns an overlay address, if known.
func (n *Node) Route(addr netip.Addr) (uuid.UUID, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	id, ok := n.routes[addr]
	return id, ok
}

func (n *Node) acceptLoop(ctx context.Context) error {
	for {
		conn, err := n.cfg.Listener.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go func() {
			s, err := n.cfg.Sessions.CreateSessionFromConnection(conn)
			if err != nil {
				n.cfg.Logf("mesh: inbound handshake from %s failed: %v", conn.RemoteAddr(), err)
				return
			}
			n.cfg.Logf("mesh: session with %s established (inbound from %s)", s.PeerID(), conn.RemoteAddr())
			if !n.knownPeer(s.PeerID()) {
				n.requestRefresh()
			}
			n.readSession(ctx, s)
		}()
	}
}

func (n *Node) pollLoop(ctx context.Context) error {
	ticker := time.NewTicker(n.cfg.PollInterval)
	defer ticker.Stop()
	for {
		n.refreshPeers(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-n.refresh:
		}
	}
}

func (n *Node) requestRefresh() {
	select {
	case n.refresh <- struct{}{}:
	default:
	}
}

// refreshPeers updates the peer table and routes from discovery, then dials
// any peer this node is responsible for connecting to.
func (n *Node) refreshPeers(ctx context.Context) {
	records, err := n.cfg.Peers.ListPeers(ctx)
	if err != nil {
		if ctx.Err() == nil {
			n.cfg.Logf("mesh: listing peers failed: %v", err)
		}
		return
	}

	peers := make(map[uuid.UUID]discovery.PeerRecord, len(records))
	routes := make(map[netip.Addr]uuid.UUID, len(records))
	for _, record := range records {
		if record.ID == n.self {
			continue
		}
		peers[record.ID] = record
		routes[record.VPNIP] = record.ID
	}

	n.mu.Lock()
	n.peers = peers
	n.routes = routes
	n.mu.Unlock()

	for _, record := range peers {
		n.maybeDial(ctx, record)
	}
}

// maybeDial dials record if this node has the lower ID, has no session with the
// peer, is not already dialing it, and is not backing off. Having exactly one
// side dial keeps each pair of peers to a single session.
func (n *Node) maybeDial(ctx context.Context, record discovery.PeerRecord) {
	if bytes.Compare(n.self[:], record.ID[:]) >= 0 {
		return
	}
	if _, ok := n.cfg.Sessions.GetSessionByPeerID(record.ID); ok {
		return
	}

	n.mu.Lock()
	if n.dialing[record.ID] || time.Now().Before(n.backoff[record.ID].next) {
		n.mu.Unlock()
		return
	}
	n.dialing[record.ID] = true
	n.mu.Unlock()

	go func() {
		s, err := n.cfg.Sessions.CreateSession(session.PeerInfo{
			ID:      record.ID,
			Address: net.TCPAddrFromAddrPort(record.Address),
		})

		n.mu.Lock()
		delete(n.dialing, record.ID)
		if err != nil {
			b := n.backoff[record.ID]
			b.delay = min(max(2*b.delay, n.cfg.MinBackoff), n.cfg.MaxBackoff)
			b.next = time.Now().Add(b.delay)
			n.backoff[record.ID] = b
		} else {
			delete(n.backoff, record.ID)
		}
		n.mu.Unlock()

		if err != nil {
			if ctx.Err() == nil {
				n.cfg.Logf("mesh: dialing %s at %s failed: %v", record.ID, record.Address, err)
			}
			return
		}
		n.cfg.Logf("mesh: session with %s established (dialed %s)", record.ID, record.Address)
		n.readSession(ctx, s)
	}()
}

// readSession writes packets from s to the device until the session ends.
func (n *Node) readSession(ctx context.Context, s *session.Session) {
	defer func() {
		n.cfg.Sessions.RemoveSession(s.SessionID())
		if ctx.Err() == nil {
			n.cfg.Logf("mesh: session with %s closed", s.PeerID())
			n.requestRefresh() // reconnect promptly
		}
	}()

	peerID := s.PeerID()
	for {
		packet, err := s.Read()
		if err != nil {
			return
		}
		src, _, ok := ipv4Addresses(packet)
		if !ok || !n.ownsAddress(peerID, src) {
			continue // not IPv4, or spoofed / unknown source
		}
		if _, err := n.cfg.Device.Write(packet); err != nil && ctx.Err() == nil {
			n.cfg.Logf("mesh: writing packet to device failed: %v", err)
		}
	}
}

// deviceLoop sends packets read from the device to the peer that owns the destination.
func (n *Node) deviceLoop(ctx context.Context) error {
	buf := make([]byte, 1<<16)
	for {
		size, err := n.cfg.Device.Read(buf)
		if err != nil {
			return fmt.Errorf("read device: %w", err)
		}
		packet := buf[:size]
		_, dst, ok := ipv4Addresses(packet)
		if !ok {
			continue
		}
		peerID, ok := n.Route(dst)
		if !ok {
			continue
		}
		s, ok := n.cfg.Sessions.GetSessionByPeerID(peerID)
		if !ok {
			continue
		}
		// A failed send means the session is dying; its reader removes it.
		_ = s.Send(packet)
	}
}

func (n *Node) keepaliveLoop(ctx context.Context) error {
	ticker := time.NewTicker(n.cfg.KeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for _, s := range n.cfg.Sessions.Sessions() {
				_ = s.SendKeepalive()
			}
		}
	}
}

func (n *Node) knownPeer(id uuid.UUID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.peers[id]
	return ok
}

func (n *Node) ownsAddress(id uuid.UUID, addr netip.Addr) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	record, ok := n.peers[id]
	return ok && record.VPNIP == addr
}
