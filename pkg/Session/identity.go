package session

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	"github.com/google/uuid"
)

// Errors related to client identity
var (
	ErrInvalidCertificate = errors.New("invalid certificate")
	ErrIdentityNotLoaded  = errors.New("client identity not loaded")
	ErrIdentityLocked     = errors.New("identity is locked")
)

// ClientIdentity contains the information about the local client,
// including its certificates, keys, and identity information
type ClientIdentity struct {
	// mutex for synchronized access to identity data
	mu sync.RWMutex
	// ID is a unique identifier for this client
	ID uuid.NullUUID
	// Certificate is the client's certificate for authentication
	Certificate *x509.Certificate // PrivateKey is the client's private key corresponding to the certificate
	// This is sensitive information that should be protected
	PrivateKey ed25519.PrivateKey
	// certificate verifier
	Verifier *certs.ClientCertificateVerifier // Used to verify peer certificates
	// CreatedAt tracks when this identity was created
	CreatedAt time.Time
	// ExpiresAt tracks when this identity expires (typically from certificate)
	ExpiresAt time.Time
	// DeviceInfo contains information about the client device
	DeviceInfo map[string]string
	// IsLocked indicates if the identity is currently locked (requiring authentication)
	isLocked bool
	// Additional metadata
	Metadata map[string]interface{}
}

// NewClientIdentity creates a new client identity
func NewClientIdentity() *ClientIdentity {
	return &ClientIdentity{
		ID:         uuid.NullUUID{Valid: false},
		CreatedAt:  time.Now(),
		DeviceInfo: make(map[string]string),
		Metadata:   make(map[string]interface{}),
		isLocked:   false,
	}
}

// LoadCertificate loads a certificate from a PEM-encoded byte array
func (c *ClientIdentity) LoadCertificate(certData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return ErrInvalidCertificate
	}

	c.Certificate = cert

	// If certificate has a subject with CommonName, use it as ID
	if cert.Subject.CommonName != "" {
		id, err := uuid.Parse(cert.Subject.CommonName)
		if err == nil {
			c.ID = uuid.NullUUID{UUID: id, Valid: true}
		} else {
			c.ID = uuid.NullUUID{Valid: false} // Reset ID if parsing fails
		}
	}

	// Set expiration time from certificate
	c.ExpiresAt = cert.NotAfter

	return nil
}

// IsExpired checks if the identity has expired
func (c *ClientIdentity) IsExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ExpiresAt.IsZero() {
		return false
	}

	return time.Now().After(c.ExpiresAt)
}

// Lock locks the identity, requiring authentication for sensitive operations
func (c *ClientIdentity) Lock() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isLocked = true
}

// Unlock unlocks the identity after authentication
func (c *ClientIdentity) Unlock(authToken string) error {
	// In a real implementation, this would verify the auth token
	// For now, we'll just unlock the identity

	c.mu.Lock()
	defer c.mu.Unlock()
	c.isLocked = false
	return nil
}

// GetPeerInfo returns a PeerInfo struct with this client's information
func (c *ClientIdentity) GetPeerInfo() (PeerInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create a PeerInfo for this client
	peer := PeerInfo{
		ID: c.ID,
	}

	// If we have a certificate, include it
	if c.Certificate != nil {
		peer.Certificate = *c.Certificate
	}

	return peer, nil
}

// ClearSensitiveData securely clears any sensitive data in memory
func (c *ClientIdentity) ClearSensitiveData() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear the private key
	c.PrivateKey = nil

}
