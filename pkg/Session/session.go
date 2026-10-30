package session

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"uuid"

	aes "github.com/JacobSartin/SMESH-VPN/pkg/AES"
	auth "github.com/JacobSartin/SMESH-VPN/pkg/Auth"
	network "github.com/JacobSartin/SMESH-VPN/pkg/Network"
	pqxdh "github.com/JacobSartin/SMESH-VPN/pkg/PQXDH"
)

// Status represents the current state of a session
type Status int

const (
	// StatusInitializing means the session is being set up
	StatusInitializing Status = iota
	// StatusEstablished means the session is active and authenticated
	StatusEstablished
	// StatusClosed means the session has been terminated
	StatusClosed
)

// handshakeTimeout bounds dialing and the whole key exchange. Tests shorten it.
var handshakeTimeout = 10 * time.Second

// The first handshake frame starts with a protocol version and a mode byte so
// that peers configured differently fail with a clear error.
const (
	protocolVersion              byte = 1
	handshakeModeUnauthenticated byte = 0
	handshakeModeAuthenticated   byte = 1
)

// Frame types carried as the first plaintext byte of every encrypted frame.
const (
	frameData      byte = 0
	frameKeepalive byte = 1
)

// Errors related to session management
var (
	ErrSessionClosed         = errors.New("session has been closed")
	ErrInvalidPeer           = errors.New("invalid peer information")
	ErrUnexpectedPeer        = errors.New("peer certificate does not match the expected peer ID")
	ErrHandshakeMismatch     = errors.New("peer uses an incompatible handshake")
	ErrSessionNotEstablished = errors.New("session not established")
)

type unauthenticatedHandshakeHello struct {
	PQPublicKey []byte    `json:"pq_public_key"`
	ECPublicKey []byte    `json:"ec_public_key"`
	ID          uuid.UUID `json:"id"`
}

type unauthenticatedHandshakeResponse struct {
	ECPublicKey []byte `json:"ec_public_key"`
	Ciphertext  []byte `json:"ciphertext"`
}

// PeerInfo contains information about a peer in the VPN mesh
type PeerInfo struct {
	// ID is the peer's client ID. For authenticated sessions it comes from the peer's certificate.
	ID uuid.UUID
	// Address is the network address of the peer
	Address net.Addr
	// Certificate is the peer's verified certificate, if the session is authenticated
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
	// writeMu serializes frames written to connection
	writeMu sync.Mutex
	// peer contains information about the remote peer
	peer PeerInfo
	// cipher is the AES encryption instance
	cipher *aes.AES256
	// status tracks the current session state
	status Status
	// established records when the session key was agreed
	established time.Time
	// lastActivity records the last time a frame was received from the peer
	lastActivity time.Time
	// closed is set to true when the session is terminated
	closed bool
	// sessionID is a unique identifier for this session
	sessionID uuid.UUID
}

// NewSession dials the peer and performs the key exchange. With an authenticated
// identity, the peer's certificate must carry peer.ID. Cancelling ctx aborts
// the dial and the handshake.
func NewSession(ctx context.Context, peer PeerInfo, identity *ClientIdentity) (*Session, error) {
	if peer.ID == uuid.Nil() || peer.Address == nil {
		return nil, ErrInvalidPeer
	}

	dialer := net.Dialer{Timeout: handshakeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", peer.Address.String())
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })

	session := &Session{
		connection: conn,
		peer:       peer,
		status:     StatusInitializing,
		sessionID:  uuid.NewV7(),
	}

	err = session.EstablishKeyExchange(identity)
	if !stop() {
		// ctx was cancelled and the connection closed, whether or not the handshake finished.
		session.Close()
		return nil, context.Cause(ctx)
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to establish key exchange: %w", err)
	}

	return session, nil
}

// NewSessionFromConn creates a new session initiated by the other side
func NewSessionFromConn(conn net.Conn, identity *ClientIdentity) (*Session, error) {
	if conn == nil {
		return nil, errors.New("connection cannot be nil")
	}

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	var (
		session *Session
		err     error
	)
	if hasAuthenticatedIdentity(identity) {
		session, err = newAuthenticatedSessionFromConn(conn, identity)
	} else {
		session, err = newUnauthenticatedSessionFromConn(conn)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	return session, nil
}

func newAuthenticatedSessionFromConn(conn net.Conn, identity *ClientIdentity) (*Session, error) {
	helloBytes, err := recvHandshake(conn, handshakeModeAuthenticated)
	if err != nil {
		return nil, err
	}

	hello := &auth.AuthenticatedHandshakeHello{}
	if err := json.Unmarshal(helloBytes, hello); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hello: %w", err)
	}

	exchange, err := auth.NewAuthenticatedPQXDHServer(identity.Certificate, identity.PrivateKey, identity.Verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated PQXDH server: %w", err)
	}

	// ProcessClientHello verifies the certificate and returns the client ID it carries.
	response, key, peerID, err := exchange.ProcessClientHello(hello)
	if err != nil {
		return nil, fmt.Errorf("failed to process client hello: %w", err)
	}

	peerCert, err := x509.ParseCertificate(hello.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer certificate: %w", err)
	}

	cipher, err := aes.NewAES256(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		cipher.Close()
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	if err := network.SendWithLen(conn, responseBytes); err != nil {
		cipher.Close()
		return nil, fmt.Errorf("failed to send response: %w", err)
	}

	now := time.Now()
	return &Session{
		connection: conn,
		peer: PeerInfo{
			ID:          peerID,
			Address:     conn.RemoteAddr(),
			Certificate: *peerCert,
			LastSeen:    now,
		},
		cipher:       cipher,
		status:       StatusEstablished,
		established:  now,
		lastActivity: now,
		sessionID:    uuid.NewV7(),
	}, nil
}

// EstablishKeyExchange performs the PQXDH key exchange and sets up the encryption
func (s *Session) EstablishKeyExchange(identity *ClientIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrSessionClosed
	}

	_ = s.connection.SetDeadline(time.Now().Add(handshakeTimeout))
	defer s.connection.SetDeadline(time.Time{})

	if !hasAuthenticatedIdentity(identity) {
		return s.establishUnauthenticatedKeyExchange(identity)
	}

	exchange, err := auth.NewAuthenticatedPQXDHClient(identity.Certificate, identity.PrivateKey, identity.Verifier)
	if err != nil {
		return fmt.Errorf("failed to create authenticated PQXDH client: %w", err)
	}
	hello, err := exchange.CreateClientHello()
	if err != nil {
		return err
	}
	helloBytes, err := json.Marshal(hello)
	if err != nil {
		return err
	}

	if err := sendHandshake(s.connection, handshakeModeAuthenticated, helloBytes); err != nil {
		return fmt.Errorf("failed to send hello message: %w", err)
	}

	responseBytes, err := network.RecvWithLen(s.connection)
	if err != nil {
		return fmt.Errorf("failed to receive response: %w", err)
	}

	response := &auth.AuthenticatedHandshakeResponse{}
	if err := json.Unmarshal(responseBytes, response); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	key, peerID, err := exchange.ProcessServerResponse(response)
	if err != nil {
		return fmt.Errorf("failed to process server response: %w", err)
	}
	if s.peer.ID != uuid.Nil() && s.peer.ID != peerID {
		return ErrUnexpectedPeer
	}
	peerCert, err := x509.ParseCertificate(response.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse peer certificate: %w", err)
	}

	cipher, err := aes.NewAES256(key)
	if err != nil {
		return fmt.Errorf("failed to initialize AES cipher: %w", err)
	}

	now := time.Now()
	s.peer.ID = peerID
	s.peer.Certificate = *peerCert
	s.peer.LastSeen = now
	s.cipher = cipher
	s.status = StatusEstablished
	s.established = now
	s.lastActivity = now

	return nil
}

// Send encrypts and sends a data frame to the peer
func (s *Session) Send(data []byte) error {
	frame := make([]byte, 1+len(data))
	frame[0] = frameData
	copy(frame[1:], data)
	return s.sendFrame(frame)
}

// SendKeepalive sends an empty frame so the peer knows this side is alive.
func (s *Session) SendKeepalive() error {
	return s.sendFrame([]byte{frameKeepalive})
}

func (s *Session) sendFrame(frame []byte) error {
	s.mu.RLock()
	conn := s.connection
	cipher := s.cipher
	closed := s.closed
	status := s.status
	s.mu.RUnlock()

	if closed || conn == nil {
		return ErrSessionClosed
	}
	if status != StatusEstablished || cipher == nil {
		return ErrSessionNotEstablished
	}

	encrypted, err := cipher.Encrypt(frame)
	if err != nil {
		return err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := network.SendWithLen(conn, encrypted); err != nil {
		return fmt.Errorf("failed to write to connection: %w", err)
	}
	return nil
}

// Read blocks until the next data frame arrives and returns its payload.
// Keepalive frames are consumed silently.
func (s *Session) Read() ([]byte, error) {
	for {
		s.mu.RLock()
		conn := s.connection
		closed := s.closed
		s.mu.RUnlock()
		if closed || conn == nil {
			return nil, ErrSessionClosed
		}

		encrypted, err := network.RecvWithLen(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to read from connection: %w", err)
		}

		frame, err := s.decrypt(encrypted)
		if err != nil {
			return nil, err
		}
		if len(frame) == 0 {
			return nil, errors.New("received empty frame")
		}

		switch frame[0] {
		case frameData:
			return frame[1:], nil
		case frameKeepalive:
			continue
		default:
			return nil, fmt.Errorf("unknown frame type %d", frame[0])
		}
	}
}

func (s *Session) decrypt(encryptedData []byte) ([]byte, error) {
	s.mu.RLock()
	closed := s.closed
	status := s.status
	cipher := s.cipher
	s.mu.RUnlock()

	if closed {
		return nil, ErrSessionClosed
	}
	if status != StatusEstablished || cipher == nil {
		return nil, ErrSessionNotEstablished
	}

	decrypted, err := cipher.Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	s.mu.Lock()
	s.lastActivity = now
	s.peer.LastSeen = now
	s.mu.Unlock()

	return decrypted, nil
}

// Close terminates the session and securely wipes any sensitive data
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil // Already closed
	}

	s.closed = true
	s.status = StatusClosed

	if s.cipher != nil {
		s.cipher.Close()
		s.cipher = nil
	}

	if s.connection != nil {
		err := s.connection.Close()
		s.connection = nil
		if err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

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

// PeerID returns the remote peer's ID.
func (s *Session) PeerID() uuid.UUID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peer.ID
}

// SessionID returns the unique ID for this session.
func (s *Session) SessionID() uuid.UUID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// IdleTime returns how long it has been since a frame was received from the peer.
func (s *Session) IdleTime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.lastActivity)
}

// KeyAge returns how long the current session key has been in use.
func (s *Session) KeyAge() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.established)
}

func hasAuthenticatedIdentity(identity *ClientIdentity) bool {
	return identity != nil && identity.Certificate != nil && identity.PrivateKey != nil && identity.Verifier != nil
}

// sendHandshake writes the first handshake frame, prefixed with version and mode.
func sendHandshake(conn net.Conn, mode byte, payload []byte) error {
	frame := make([]byte, 2+len(payload))
	frame[0] = protocolVersion
	frame[1] = mode
	copy(frame[2:], payload)
	return network.SendWithLen(conn, frame)
}

// recvHandshake reads the first handshake frame and checks version and mode.
func recvHandshake(conn net.Conn, wantMode byte) ([]byte, error) {
	frame, err := network.RecvWithLen(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read hello message: %w", err)
	}
	if len(frame) < 2 {
		return nil, fmt.Errorf("%w: hello too short", ErrHandshakeMismatch)
	}
	if frame[0] != protocolVersion {
		return nil, fmt.Errorf("%w: protocol version %d, want %d", ErrHandshakeMismatch, frame[0], protocolVersion)
	}
	if frame[1] != wantMode {
		return nil, fmt.Errorf("%w: peer handshake mode %s, this node requires %s", ErrHandshakeMismatch, modeName(frame[1]), modeName(wantMode))
	}
	return frame[2:], nil
}

func modeName(mode byte) string {
	switch mode {
	case handshakeModeAuthenticated:
		return "authenticated"
	case handshakeModeUnauthenticated:
		return "unauthenticated"
	default:
		return fmt.Sprintf("unknown(%d)", mode)
	}
}

// establishUnauthenticatedKeyExchange runs PQXDH without certificates. Peers are
// not authenticated, so this path is only for tests and development.
func (s *Session) establishUnauthenticatedKeyExchange(identity *ClientIdentity) error {
	exchange, err := pqxdh.NewPQXDHClient()
	if err != nil {
		return fmt.Errorf("failed to create PQXDH client: %w", err)
	}

	hello := unauthenticatedHandshakeHello{
		PQPublicKey: exchange.GetPQPublicKey().Bytes(),
		ECPublicKey: exchange.GetECPublicKey().Bytes(),
	}
	if identity != nil {
		hello.ID = identity.ID
	}
	if hello.ID == uuid.Nil() {
		hello.ID = uuid.NewV7()
	}

	helloBytes, err := json.Marshal(hello)
	if err != nil {
		return fmt.Errorf("failed to marshal hello: %w", err)
	}

	if err := sendHandshake(s.connection, handshakeModeUnauthenticated, helloBytes); err != nil {
		return fmt.Errorf("failed to send hello message: %w", err)
	}

	responseBytes, err := network.RecvWithLen(s.connection)
	if err != nil {
		return fmt.Errorf("failed to receive response: %w", err)
	}

	var response unauthenticatedHandshakeResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	serverECPubKey, err := pqxdh.ParseECPublicKey(response.ECPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse server EC public key: %w", err)
	}

	key, err := pqxdh.ClientKeyExchange(serverECPubKey, response.Ciphertext, *exchange)
	if err != nil {
		return fmt.Errorf("PQXDH client key exchange failed: %w", err)
	}

	cipher, err := aes.NewAES256(key)
	if err != nil {
		return fmt.Errorf("failed to initialize AES cipher: %w", err)
	}

	now := time.Now()
	s.cipher = cipher
	s.status = StatusEstablished
	s.established = now
	s.lastActivity = now

	return nil
}

func newUnauthenticatedSessionFromConn(conn net.Conn) (*Session, error) {
	helloBytes, err := recvHandshake(conn, handshakeModeUnauthenticated)
	if err != nil {
		return nil, err
	}

	var hello unauthenticatedHandshakeHello
	if err := json.Unmarshal(helloBytes, &hello); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hello: %w", err)
	}

	clientPQPubKey, err := pqxdh.ParsePQPublicKey(hello.PQPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client PQ public key: %w", err)
	}

	clientECPubKey, err := pqxdh.ParseECPublicKey(hello.ECPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client EC public key: %w", err)
	}

	exchange, err := pqxdh.NewPQXDHServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create PQXDH server: %w", err)
	}

	key, ciphertext, err := pqxdh.ServerKeyExchange(clientPQPubKey, clientECPubKey, *exchange)
	if err != nil {
		return nil, fmt.Errorf("PQXDH server key exchange failed: %w", err)
	}

	cipher, err := aes.NewAES256(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	response := unauthenticatedHandshakeResponse{
		ECPublicKey: exchange.GetECPublicKey().Bytes(),
		Ciphertext:  ciphertext,
	}
	responseBytes, err := json.Marshal(response)
	if err != nil {
		cipher.Close()
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	if err := network.SendWithLen(conn, responseBytes); err != nil {
		cipher.Close()
		return nil, fmt.Errorf("failed to send response: %w", err)
	}

	peerID := hello.ID
	if peerID == uuid.Nil() {
		peerID = uuid.NewV7()
	}

	now := time.Now()
	return &Session{
		connection:   conn,
		peer:         PeerInfo{ID: peerID, Address: conn.RemoteAddr(), LastSeen: now},
		cipher:       cipher,
		status:       StatusEstablished,
		established:  now,
		lastActivity: now,
		sessionID:    uuid.NewV7(),
	}, nil
}
