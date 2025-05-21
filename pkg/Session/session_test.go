package session

import (
	"testing"
	"time"
)

// TestSessionCreation tests creating a new session with a client identity
func TestSessionCreation(t *testing.T) {
	// Create a mock identity
	identity := NewClientIdentity()

	// Create a mock peer
	peer := PeerInfo{
		ID:      "peer1",
		Address: &mockAddr{network: "tcp", address: "192.168.1.100:51820"},
	}

	// Create a new session
	sess, err := NewSession(peer, identity)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Check initial status
	if sess.Status() != StatusInitializing {
		t.Errorf("Expected status %v, got %v", StatusInitializing, sess.Status())
	}

	// Check peer info
	peerInfo := sess.PeerInfo()
	if peerInfo.ID != peer.ID {
		t.Errorf("Expected peer ID %s, got %s", peer.ID, peerInfo.ID)
	}

	// Check local identity
	localIdentity, err := sess.GetLocalIdentity()
	if err != nil {
		t.Errorf("Failed to get local identity: %v", err)
	}
	if localIdentity != identity {
		t.Errorf("Expected identity to match the provided identity")
	}
}

// TestSessionEstablishment tests establishing a session
func TestSessionEstablishment(t *testing.T) {
	// Create a mock identity
	identity := NewClientIdentity()

	// Create a mock peer
	peer := PeerInfo{
		ID:      "peer1",
		Address: &mockAddr{network: "udp", address: "192.168.1.100:51820"},
	}

	// Create a new session
	sess, err := NewSession(peer, identity)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Establish the session
	err = sess.EstablishKeyExchange()
	if err != nil {
		t.Fatalf("Failed to establish session: %v", err)
	}

	// Check status
	if sess.Status() != StatusEstablished {
		t.Errorf("Expected status %v, got %v", StatusEstablished, sess.Status())
	}
}

// TestSessionClosure tests closing a session
func TestSessionClosure(t *testing.T) {
	// Create a mock identity
	identity := NewClientIdentity()

	// Create a mock peer
	peer := PeerInfo{
		ID:      "peer1",
		Address: &mockAddr{network: "udp", address: "192.168.1.100:51820"},
	}

	// Create a new session
	sess, err := NewSession(peer, identity)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Close the session
	err = sess.Close()
	if err != nil {
		t.Fatalf("Failed to close session: %v", err)
	}

	// Check status
	if sess.Status() != StatusClosed {
		t.Errorf("Expected status %v, got %v", StatusClosed, sess.Status())
	}

	// Verify operations fail on closed session
	_, err = sess.Send([]byte("test"))
	if err != ErrSessionClosed {
		t.Errorf("Expected %v, got %v", ErrSessionClosed, err)
	}
}

// TestSessionManager tests the session manager
func TestSessionManager(t *testing.T) {
	// Create a client identity
	identity := NewClientIdentity()

	// Create a session manager with short intervals for testing
	manager := NewSessionManager(100*time.Millisecond, 300*time.Millisecond, 500*time.Millisecond, identity)

	// Make sure to clean up
	defer manager.Shutdown()

	// Create some test sessions
	peers := []PeerInfo{
		{
			ID:      "peer1",
			Address: &mockAddr{network: "udp", address: "192.168.1.100:51820"},
		},
		{
			ID:      "peer2",
			Address: &mockAddr{network: "udp", address: "192.168.1.101:51820"},
		},
	}

	for _, peer := range peers {
		// Use CreateSession to ensure identity is properly passed
		_, err := manager.CreateSession(peer)
		if err != nil {
			t.Fatalf("Failed to create session for %s: %v", peer.ID, err)
		}
	}

	// Check count
	if manager.Count() != len(peers) {
		t.Errorf("Expected %d sessions, got %d", len(peers), manager.Count())
	} // Lookup sessions
	for _, peer := range peers {
		// By peer ID
		sess, exists := manager.GetSessionByPeerID(peer.ID)
		if !exists {
			t.Errorf("Session for peer %s not found", peer.ID)
			continue
		}

		// Check peer info matches
		if sess.peer.ID != peer.ID {
			t.Errorf("Wrong session returned for peer %s", peer.ID)
		}

		// By session ID (using the session we just got by peer ID)
		sessionID := sess.sessionID
		sess2, exists := manager.GetSession(sessionID)
		if !exists {
			t.Errorf("Session with ID %s not found", sessionID.String())
			continue
		}
		if sess2 != sess {
			t.Errorf("Wrong session returned for ID %s", sessionID.String())
		}
	}
	// Get the session ID of the first peer for removal
	firstPeer := peers[0]
	firstSess, exists := manager.GetSessionByPeerID(firstPeer.ID)
	if !exists {
		t.Fatalf("Cannot get first session for removal test")
	}

	// Test removal
	sessionIDToRemove := firstSess.sessionID
	manager.RemoveSession(sessionIDToRemove)
	if manager.Count() != len(peers)-1 {
		t.Errorf("Expected %d sessions after removal, got %d", len(peers)-1, manager.Count())
	}

	// Verify the session was actually removed
	_, stillExists := manager.GetSession(sessionIDToRemove)
	if stillExists {
		t.Errorf("Session should have been removed but still exists")
	}
	// test closing all sessions
	manager.CloseAll()

	// Check that only the remaining session was cleaned up (since we removed one already)
	if manager.Count() != 0 {
		t.Errorf("Expected all sessions to be cleaned up, but %d remain", manager.Count())
	}
}

// TestSessionManagerEstablish tests the EstablishSession function
func TestSessionManagerEstablish(t *testing.T) {
	// Create a client identity
	identity := NewClientIdentity()

	// Create a session manager
	manager := NewSessionManager(100*time.Millisecond, 300*time.Millisecond, 500*time.Millisecond, identity)
	defer manager.Shutdown()

	// Peer info
	peer := PeerInfo{
		ID:      "peer3",
		Address: &mockAddr{network: "udp", address: "192.168.1.102:51820"},
	}

	// Establish a session directly
	sess, err := manager.EstablishSession(peer)
	if err != nil {
		t.Fatalf("Failed to establish session: %v", err)
	}

	// Verify the session is established
	if sess.Status() != StatusEstablished {
		t.Errorf("Expected status %v, got %v", StatusEstablished, sess.Status())
	}

	// Check it's in the manager
	if manager.Count() != 1 {
		t.Errorf("Expected 1 session in manager, got %d", manager.Count())
	}

	// Lookup by peer ID
	retrievedSess, exists := manager.GetSessionByPeerID(peer.ID)
	if !exists {
		t.Errorf("Session for peer %s not found", peer.ID)
	} else if retrievedSess != sess {
		t.Errorf("Wrong session returned for peer %s", peer.ID)
	}
}

// TestIdentity tests the client identity functionality
func TestIdentity(t *testing.T) {
	// Create a client identity
	identity := NewClientIdentity()

	// Check default values
	if identity.ID == "" {
		t.Errorf("Expected identity to have a non-empty ID")
	}

	// Check expiration
	if identity.IsExpired() {
		t.Errorf("New identity should not be expired")
	}

	// Test locking/unlocking
	identity.Lock()
	err := identity.Unlock("test-token") // In a real implementation, this would verify the token
	if err != nil {
		t.Errorf("Failed to unlock identity: %v", err)
	}

	// Test peer info conversion
	peerInfo, err := identity.GetPeerInfo()
	if err != nil {
		t.Errorf("Failed to get peer info: %v", err)
	}
	if peerInfo.ID != identity.ID {
		t.Errorf("Expected peer ID to match identity ID")
	}
}

// mockAddr implements net.Addr for testing
type mockAddr struct {
	network string
	address string
}

func (m *mockAddr) Network() string {
	return m.network
}

func (m *mockAddr) String() string {
	return m.address
}
