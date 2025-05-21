package session

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/JacobSartin/SMESH-VPN/pkg/AES"
	"github.com/google/uuid"
)

// Status represents the current state of a session
type Status int

const (
	// StatusInitializing means the session is being set up
	StatusInitializing Status = iota
	// StatusEstablished means the session is active and authenticated
	StatusEstablished
	// StatusRekeying means the session is performing key rotation
	StatusRekeying
	// StatusClosed means the session has been terminated
	StatusClosed
)

// Errors related to session management
var (
	ErrSessionClosed     = errors.New("session has been closed")
	ErrInvalidPeer       = errors.New("invalid peer information")
	ErrAuthFailed        = errors.New("peer authentication failed")
	ErrKeyExchangeFailed = errors.New("key exchange failed")
	ErrSessionTimeout    = errors.New("session timed out")
)

// PeerInfo contains information about a peer in the VPN mesh
type PeerInfo struct {
	// ! use UUIDv1 for ID, should be unique across the network
	// ID is a unique identifier for the peer
	ID string
	// Address is the network address of the peer
	Address net.Addr
	// PublicKey contains the peer's public key(s) for authentication
	// This could be expanded to include both classical and PQ keys
	PQPublicKey interface{}
	ECPublicKey interface{}
	// Certificate can be used for certificate-based auth
	Certificate []byte
	// LastSeen tracks when we last had contact with this peer
	LastSeen time.Time
	// AdditionalInfo can store any extra peer metadata
	AdditionalInfo map[string]interface{}
}

// Session represents an encrypted communication session with a peer
type Session struct {
	// mutex for synchronized access to session data
	mu sync.RWMutex
	// peer contains information about the remote peer
	peer PeerInfo
	// localIdentity contains information about the local client
	localIdentity *ClientIdentity
	// cipher is the AES encryption instance
	cipher *aes.AES256
	// status tracks the current session state
	status Status
	// established records when the session was created
	established time.Time
	// lastActivity records the last time the session was used
	lastActivity time.Time
	// tunnel represents the virtual network interface
	// This would be expanded based on your tunneling implementation
	tunnel interface{}
	// closed is set to true when the session is terminated
	closed bool
	// sessionID is a unique identifier for this session
	sessionID uuid.UUID
	// Additional fields would be added as needed:
	// - Traffic statistics
	// - Quality metrics
	// - Configuration parameters
	// - Routes and forwarding rules
}

// NewSession creates a new session with the given peer
func NewSession(peer PeerInfo, identity *ClientIdentity) (*Session, error) {
	if peer.ID == "" || peer.Address == nil {
		return nil, ErrInvalidPeer
	}

	return &Session{
		peer:          peer,
		status:        StatusInitializing,
		established:   time.Now(),
		lastActivity:  time.Now(),
		closed:        false,
		sessionID:     generateSessionID(),
		localIdentity: identity,
	}, nil
}

// EstablishKeyExchange performs the PQXDH key exchange and sets up the encryption
func (s *Session) EstablishKeyExchange() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrSessionClosed
	}

	// TODO
	// This is a placeholder - actual implementation would:
	// 1. Perform PQXDH key exchange with the peer
	// 2. Initialize the AES cipher with the derived key
	// 3. Update the session status

	// For now, we'll just update the status
	s.status = StatusEstablished
	s.lastActivity = time.Now()

	return nil
}

// Send encrypts and sends data to the peer
func (s *Session) Send(data []byte) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return 0, ErrSessionClosed
	}

	if s.status != StatusEstablished {
		return 0, errors.New("session not established")
	}

	if s.cipher == nil {
		return 0, errors.New("encryption not initialized")
	}

	// Encrypt the data
	encrypted, err := s.cipher.Encrypt(data)
	if err != nil {
		return 0, err
	}

	// Update last activity
	s.lastActivity = time.Now()

	// TODO: Send the encrypted data over the network
	// In a real implementation, this would send the encrypted data over the network
	// For now, we'll just return the length that would have been sent
	return len(encrypted), nil
}

// Receive decrypts data received from the peer
func (s *Session) Receive(encryptedData []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrSessionClosed
	}

	if s.status != StatusEstablished {
		return nil, errors.New("session not established")
	}

	if s.cipher == nil {
		return nil, errors.New("encryption not initialized")
	}

	// Decrypt the data
	decrypted, err := s.cipher.Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	// Update last activity
	s.lastActivity = time.Now()

	return decrypted, nil
}

// Close terminates the session and securely wipes any sensitive data
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil // Already closed
	}

	// Clean up the cipher
	if s.cipher != nil {
		s.cipher.Close()
		s.cipher = nil
	}

	// TODO
	// Close any open connections or tunnels
	// Additional cleanup would happen here

	s.closed = true
	s.status = StatusClosed

	return nil
}

// Status returns the current session status
func (s *Session) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// PeerInfo returns information about the remote peer
func (s *Session) PeerInfo() PeerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peer
}

// IdleTime returns how long the session has been idle
func (s *Session) IdleTime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.lastActivity)
}

// RekeyIfNeeded performs key rotation if the session has been active too long
func (s *Session) RekeyIfNeeded(maxKeyAge time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrSessionClosed
	}

	keyAge := time.Since(s.established)
	if keyAge < maxKeyAge {
		// No need to rekey yet
		return nil
	}

	// Set status to rekeying
	s.status = StatusRekeying

	// TODO
	// In a real implementation, you would:
	// 1. Initiate a new key exchange
	// 2. Update the cipher with the new key
	// 3. Reset the established timestamp
	// 4. Return to established status

	// For now, we'll just update the timestamp
	s.established = time.Now()
	s.status = StatusEstablished

	return nil
}

// GetLocalIdentity returns the local client identity associated with this session
func (s *Session) GetLocalIdentity() (*ClientIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.localIdentity == nil {
		return nil, ErrIdentityNotLoaded
	}

	return s.localIdentity, nil
}

// generateSessionID creates a unique session identifier
func generateSessionID() uuid.UUID {
	return uuid.New()
}
