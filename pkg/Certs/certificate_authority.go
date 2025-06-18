package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Errors related to certificate authority operations
var (
	ErrInvalidCertificate          = errors.New("invalid certificate")
	ErrCertificateNotFound         = errors.New("certificate not found")
	ErrCertificateAlreadyExists    = errors.New("certificate already exists")
	ErrCertificateExpired          = errors.New("certificate expired")
	ErrCertificateNotYetValid      = errors.New("certificate not yet valid")
	ErrInvalidKeySize              = errors.New("invalid key size, must be 32 bytes (256 bits)")
	ErrInvalidSignature            = errors.New("invalid signature")
	ErrCertificateGenerationFailed = errors.New("certificate generation failed")
	ErrCertificateAuthorityLocked  = errors.New("certificate authority is locked")
)

// ErrCertificateRevoked is returned when a certificate is found to be revoked
var ErrCertificateRevoked = errors.New("certificate has been revoked")

// CertificateAuthority will be used by the discovery server to manage certificates
// this will sign certificates for clients
type CertificateAuthority struct {
	mu sync.RWMutex
	// ID is a unique identifier for this CA
	ID string
	// PrivateKey is the CA's private key used for signing certificates
	PrivateKey ed25519.PrivateKey
	// PublicKey is the CA's public key used for verifying certificates
	PublicKey ed25519.PublicKey
	// Certificates is a map of certificate ID to x509 certificate
	Certificates map[string]*x509.Certificate
	// CreatedAt tracks when this CA was created
	CreatedAt time.Time
	// ExpiresAt tracks when this CA expires
	ExpiresAt time.Time
	// IsLocked indicates if the CA is currently locked (requiring authentication)
	IsLocked bool
	// Metadata contains additional information about the CA
	Metadata map[string]interface{}
	// DeviceInfo contains information about the CA device
	DeviceInfo map[string]string
	// Certificate is the template used for generating new certificates
	Certificate *x509.Certificate
	// CertificateMutex is used to synchronize access to the certificate template
	CertificateMutex sync.RWMutex
	// CleanupInterval determines how often expired certificates are cleaned up
	CleanupInterval time.Duration
	// StopCleanup is a channel to signal the cleanup goroutine to stop
	StopCleanup    chan struct{} // CleanupRunning indicates if the cleanup goroutine is currently running
	CleanupRunning bool
	// Serial number management
	nextSerialNumber *big.Int // Counter for unique serial numbers
	// CRL management
	crlManager *CRLManager
}

// NewCertificateAuthority creates a new Certificate Authority for the discovery server
func NewCertificateAuthority() (*CertificateAuthority, error) {
	// Generate CA key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key pair: %w", err)
	}
	ca := &CertificateAuthority{
		ID:               uuid.New().String(),
		PrivateKey:       priv,
		PublicKey:        pub,
		Certificates:     make(map[string]*x509.Certificate),
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		IsLocked:         false,
		Metadata:         make(map[string]interface{}),
		DeviceInfo:       make(map[string]string),
		CleanupInterval:  24 * time.Hour, // Daily cleanup
		StopCleanup:      make(chan struct{}),
		nextSerialNumber: big.NewInt(2), // Start at 2 since CA uses serial number 1
	}

	// Create the CA certificate
	caCert, err := ca.createCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	} // Set the certificate template for future client certificates
	ca.Certificate = caCert

	// Initialize CRL manager
	ca.crlManager = NewCRLManager(365 * 24 * time.Hour) // 1 year CRL validity

	return ca, nil
}

// createCACertificate creates the root CA certificate
func (ca *CertificateAuthority) createCACertificate() (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "SMESH-VPN Discovery Server CA",
			Organization: []string{"SMESH-VPN"},
		}, NotBefore: ca.CreatedAt,
		NotAfter:              ca.ExpiresAt,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // Only allow end-entity certificates
	}

	// Create self-signed CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, ca.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return cert, nil
}

// IssueClientCertificate creates and signs a certificate for a VPN client
func (ca *CertificateAuthority) IssueClientCertificate(clientPubKey ed25519.PublicKey, clientID string) ([]byte, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ca.IsLocked {
		return nil, ErrCertificateAuthorityLocked
	}

	// Check if certificate already exists for this client
	if _, exists := ca.Certificates[clientID]; exists {
		return nil, ErrCertificateAlreadyExists
	}

	// Generate a unique serial number
	serialNumber := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("SMESH-VPN-Client-%s", clientID),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour), // 30 days validity
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign the certificate with the CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, clientPubKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Parse and store the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	ca.Certificates[clientID] = cert

	return certDER, nil
}

// GetCACertificate returns the CA certificate in DER format for distribution to clients
func (ca *CertificateAuthority) GetCACertificate() ([]byte, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if ca.Certificate == nil {
		return nil, fmt.Errorf("CA certificate not initialized")
	}

	return ca.Certificate.Raw, nil
}

// ValidateClientCertificate verifies that a client certificate was issued by this CA
func (ca *CertificateAuthority) ValidateClientCertificate(cert *x509.Certificate) (bool, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	// Create a certificate pool with our CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)

	// Verify the certificate
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return false, fmt.Errorf("certificate verification failed: %w", err)
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false, ErrCertificateNotYetValid
	}
	if now.After(cert.NotAfter) {
		return false, ErrCertificateExpired
	}
	// Check if the certificate is already revoked
	isRevoked, err := ca.crlManager.CheckCertificateRevocation(cert)
	if err != nil {
		return false, fmt.Errorf("failed to check certificate revocation: %w", err)
	}
	if isRevoked {
		return false, ErrCertificateRevoked
	}

	return true, nil
}

// GenerateCertificateFingerprint creates a SHA-256 fingerprint of a certificate
func (ca *CertificateAuthority) GenerateCertificateFingerprint(certDER []byte) ([]byte, error) {
	hash := sha256.Sum256(certDER)
	return hash[:], nil
}

// ListActiveCertificates returns a list of all active certificates
func (ca *CertificateAuthority) ListActiveCertificates() map[string]*x509.Certificate {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]*x509.Certificate)
	for k, v := range ca.Certificates {
		result[k] = v
	}
	return result
}

// StartCleanup begins the automatic cleanup of expired certificates
func (ca *CertificateAuthority) StartCleanup() {
	ca.mu.Lock()
	if ca.CleanupRunning {
		ca.mu.Unlock()
		return
	}
	ca.CleanupRunning = true
	ca.mu.Unlock()

	go func() {
		ticker := time.NewTicker(ca.CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ca.cleanupExpiredCertificates()
			case <-ca.StopCleanup:
				ca.mu.Lock()
				ca.CleanupRunning = false
				ca.mu.Unlock()
				return
			}
		}
	}()
}

// StopCleanupProcess stops the automatic cleanup process
func (ca *CertificateAuthority) StopCleanupProcess() {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ca.CleanupRunning {
		close(ca.StopCleanup)
		ca.StopCleanup = make(chan struct{})
	}
}

// cleanupExpiredCertificates removes expired certificates from the store
func (ca *CertificateAuthority) cleanupExpiredCertificates() {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	now := time.Now()
	for clientID, cert := range ca.Certificates {
		if now.After(cert.NotAfter) {
			delete(ca.Certificates, clientID)
		}
	}
}

// GetCRLManager returns the CRL manager for direct access to CRL operations
func (ca *CertificateAuthority) GetCRLManager() *CRLManager {
	return ca.crlManager
}

// GetCertificateTemplate returns the CA certificate template
func (ca *CertificateAuthority) GetCertificateTemplate() *x509.Certificate {
	return ca.Certificate
}

// GetPrivateKey returns the CA private key (for CRL signing)
func (ca *CertificateAuthority) GetPrivateKey() ed25519.PrivateKey {
	return ca.PrivateKey
}

// Convenient CRL delegation methods that pass the CA reference

// RevokeCertificate revokes a certificate by client ID
func (ca *CertificateAuthority) RevokeCertificate(clientID string, reasonCode int) error {
	return ca.crlManager.RevokeCertificate(clientID, reasonCode, ca)
}

// RevokeCertificateBySerial revokes a certificate by its serial number
func (ca *CertificateAuthority) RevokeCertificateBySerial(serialNumber *big.Int, reasonCode int) error {
	return ca.crlManager.RevokeCertificateBySerial(serialNumber, reasonCode, ca)
}

// GetCRL returns the current CRL in DER format
func (ca *CertificateAuthority) GetCRL() ([]byte, error) {
	return ca.crlManager.GetCRL()
}

// CheckCertificateRevocation checks if a certificate is revoked using the current CRL
func (ca *CertificateAuthority) CheckCertificateRevocation(cert *x509.Certificate) (bool, error) {
	return ca.crlManager.CheckCertificateRevocation(cert)
}
