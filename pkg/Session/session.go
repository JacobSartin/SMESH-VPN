package session

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	aes "github.com/JacobSartin/SMESH-VPN/pkg/AES"
	auth "github.com/JacobSartin/SMESH-VPN/pkg/Auth"
	network "github.com/JacobSartin/SMESH-VPN/pkg/Network"
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
	ID uuid.NullUUID
	// Address is the network address of the peer
	Address net.Addr
	// Certificate can be used for certificate-based auth
	Certificate x509.Certificate
	// LastSeen tracks when we last had contact with this peer
	LastSeen time.Time
	// AdditionalInfo can store any extra peer metadata
	AdditionalInfo map[string]interface{}
}

// Session represents an encrypted communication session with a peer
type Session struct {
	connection net.Conn // The underlying network connection for this session
	// mutex for synchronized access to session data
	mu sync.RWMutex
	// peer contains information about the remote peer
	peer PeerInfo
	// cipher is the AES encryption instance
	cipher *aes.AES256
	// status tracks the current session state
	status Status
	// established records when the session was created
	established time.Time
	// lastActivity records the last time the session was used
	lastActivity time.Time
	// tunnel represents the virtual network interface
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
	if !peer.ID.Valid || peer.Address == nil {
		return nil, ErrInvalidPeer
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	// initialize the connection
	conn, err := connect(peer.Address.String())
	if err != nil {
		return nil, err
	}

	session := &Session{
		connection:   conn,
		peer:         peer,
		status:       StatusInitializing,
		established:  time.Now(),
		lastActivity: time.Now(),
		closed:       false,
		sessionID:    id,
	}

	// Perform the key exchange to establish encryption
	if err := session.EstablishKeyExchange(identity); err != nil {
		conn.Close() // Close the connection if key exchange fails
		return nil, fmt.Errorf("failed to establish key exchange: %w", err)
	}

	return session, nil
}

// NewSessionFromConn creates a new session initiated by the other side
func NewSessionFromConn(conn net.Conn, identity *ClientIdentity) (*Session, error) {
	if conn == nil {
		return nil, errors.New("connection cannot be nil")
	}

	// Read the peer's hello message
	helloBytes, err := network.RecvWithLen(conn)
	if err != nil {
		conn.Close() // Close the connection if reading fails
		return nil, fmt.Errorf("failed to read hello message: %w", err)
	}

	// Unmarshal the hello message
	hello := &auth.AuthenticatedHandshakeHello{}
	if err := hello.UnmarshalJSON(helloBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	peerCert, err := x509.ParseCertificate(hello.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer certificate: %w", err)
	}

	// create a new session with the peer information
	peer := PeerInfo{
		ID:          hello.ID,
		Address:     conn.RemoteAddr(),
		Certificate: *peerCert,
		LastSeen:    time.Now(),
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	session := &Session{
		connection:   conn,
		peer:         peer,
		status:       StatusInitializing,
		established:  time.Now(),
		lastActivity: time.Now(),
		closed:       false,
		sessionID:    id,
	}

	// finish the exchange
	exchange, err := auth.NewAuthenticatedPQXDHServer(identity.Certificate, identity.PrivateKey, identity.Verifier)
	if err != nil {
		conn.Close() // Close the connection if exchange creation fails
		return nil, fmt.Errorf("failed to create authenticated PQXDH server: %w", err)
	}

	response, key, err := exchange.ProcessClientHello(hello)
	if err != nil {
		conn.Close() // Close the connection if processing fails
		return nil, fmt.Errorf("failed to process client hello: %w", err)
	}

	// set the session's cipher with the derived key
	cipher, err := aes.NewAES256(key)
	if err != nil {
		conn.Close() // Close the connection if cipher creation fails
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	session.cipher = cipher

	// send the response back to the client
	responseBytes, err := response.MarshalJSON()
	if err != nil {
		conn.Close() // Close the connection if marshaling fails
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	err = network.SendWithLen(conn, responseBytes)
	if err != nil {
		conn.Close() // Close the connection if sending fails
		return nil, fmt.Errorf("failed to send response: %w", err)
	}

	// Update session status to established
	session.status = StatusEstablished
	session.lastActivity = time.Now()

	return session, nil
}

func connect(remote string) (net.Conn, error) {
	conn, err := net.Dial("tcp", remote)
	if err != nil {
		return nil, err
	}

	// TODO could add a timeout here

	return conn, nil
}

// EstablishKeyExchange performs the PQXDH key exchange and sets up the encryption
func (s *Session) EstablishKeyExchange(identity *ClientIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrSessionClosed
	}

	exchange := auth.NewAuthenticatedPQXDHClient(identity.Certificate, identity.PrivateKey, identity.Verifier, identity.ID)
	hello, err := exchange.CreateClientHello()
	if err != nil {
		return err
	}
	helloBytes, err := hello.MarshalJSON()
	if err != nil {
		return err
	}

	// Send the hello message to the server
	err = network.SendWithLen(s.connection, helloBytes)
	if err != nil {
		return fmt.Errorf("failed to send hello message: %w", err)
	}

	responseBytes, err := network.RecvWithLen(s.connection)
	if err != nil {
		return fmt.Errorf("failed to receive response: %w", err)
	}

	response := &auth.AuthenticatedHandshakeResponse{}
	if err := response.UnmarshalJSON(responseBytes); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	key, err := exchange.ProcessServerResponse(response)
	if err != nil {
		return fmt.Errorf("failed to process server response: %w", err)
	}
	// Initialize the AES cipher with the derived key
	cipher, err := aes.NewAES256(key)
	if err != nil {
		return fmt.Errorf("failed to initialize AES cipher: %w", err)
	}
	// Set the cipher in the session
	s.cipher = cipher

	// Update session status to established
	s.status = StatusEstablished
	s.lastActivity = time.Now()

	return nil
}

// Send encrypts and sends data to the peer
func (s *Session) Send(data []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrSessionClosed
	}

	if s.status != StatusEstablished {
		return errors.New("session not established")
	}

	if s.cipher == nil {
		return errors.New("encryption not initialized")
	}

	// Encrypt the data
	encrypted, err := s.cipher.Encrypt(data)
	if err != nil {
		return err
	}

	// Update last activity
	s.lastActivity = time.Now()

	// TODO improve error handling and check len?
	_, err = s.connection.Write(encrypted)
	if err != nil {
		return err
	}
	return nil
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

	if s.connection != nil {
		err := s.connection.Close()
		if err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
		s.connection = nil
	}

	// TODO
	// Close any open tunnels
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
