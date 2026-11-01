package session

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"
	"uuid"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
)

// Errors related to client identity
var (
	ErrInvalidCertificate = errors.New("invalid certificate")
)

// ClientIdentity contains the information about the local client,
// including its certificates, keys, and identity information
type ClientIdentity struct {
	// mutex for synchronized access to identity data
	mu sync.RWMutex
	// ID is a unique identifier for this client
	ID uuid.UUID
	// Certificate is the client's certificate for authentication
	Certificate *x509.Certificate
	// PrivateKey is the client's private key corresponding to the certificate.
	// This is sensitive information that should be protected
	PrivateKey *mldsa.PrivateKey
	// certificate verifier
	Verifier *certs.ClientCertificateVerifier // Used to verify peer certificates
	// CACertificate is the trusted network CA, also used to verify the discovery server
	CACertificate *x509.Certificate
	// CreatedAt tracks when this identity was created
	CreatedAt time.Time
	// ExpiresAt tracks when this identity expires (typically from certificate)
	ExpiresAt time.Time
	// DeviceInfo contains information about the client device
	DeviceInfo map[string]string
	// IsLocked indicates if the identity is currently locked (requiring authentication)
	isLocked bool
	// Additional metadata
	Metadata map[string]any
}

// NewClientIdentity creates a new client identity
func NewClientIdentity() *ClientIdentity {
	return &ClientIdentity{
		CreatedAt:  time.Now(),
		DeviceInfo: make(map[string]string),
		Metadata:   make(map[string]any),
		isLocked:   false,
	}
}

// LoadCertificate loads a DER-encoded certificate
func (c *ClientIdentity) LoadCertificate(certData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return ErrInvalidCertificate
	}

	c.Certificate = cert

	if id, err := certs.ClientIDFromCertificate(cert); err == nil {
		c.ID = id
	} else {
		c.ID = uuid.Nil()
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

// LoadClientIdentity loads a client certificate, its private key, and the trusted
// CA certificate from PEM files, as written by the server's issue-client command.
func LoadClientIdentity(certPath, keyPath, caPath string) (*ClientIdentity, error) {
	cert, err := certs.LoadCertificateFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	key, err := certs.LoadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client key: %w", err)
	}
	caCert, err := certs.LoadCertificateFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("load CA certificate: %w", err)
	}
	return NewAuthenticatedClientIdentity(cert, key, caCert)
}

// NewAuthenticatedClientIdentity builds an identity from a client certificate
// and key, checking that the certificate is valid under caCert.
func NewAuthenticatedClientIdentity(cert *x509.Certificate, key *mldsa.PrivateKey, caCert *x509.Certificate) (*ClientIdentity, error) {
	if !key.PublicKey().Equal(cert.PublicKey) {
		return nil, errors.New("client key does not match client certificate")
	}
	verifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		return nil, err
	}
	if _, err := verifier.VerifyPeerCertificate(cert.Raw); err != nil {
		return nil, fmt.Errorf("client certificate is not valid under the CA: %w", err)
	}
	id, err := certs.ClientIDFromCertificate(cert)
	if err != nil {
		return nil, err
	}

	identity := NewClientIdentity()
	identity.ID = id
	identity.Certificate = cert
	identity.PrivateKey = key
	identity.Verifier = verifier
	identity.CACertificate = caCert
	identity.ExpiresAt = cert.NotAfter
	return identity, nil
}

// TLSCertificate returns the identity as a TLS client certificate.
func (c *ClientIdentity) TLSCertificate() (tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Certificate == nil || c.PrivateKey == nil {
		return tls.Certificate{}, errors.New("identity has no certificate")
	}
	return tls.Certificate{
		Certificate: [][]byte{c.Certificate.Raw},
		PrivateKey:  c.PrivateKey,
		Leaf:        c.Certificate,
	}, nil
}
