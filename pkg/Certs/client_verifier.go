package certs

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ClientCertificateVerifier handles certificate verification on the client side
// Clients only need this to verify other peer certificates using the CA's public certificate
type ClientCertificateVerifier struct {
	// caCert is the discovery server's CA certificate (pre-shared)
	caCert *x509.Certificate
	// trustedFingerprints is a cache of known certificate fingerprints for efficient handshakes
	trustedFingerprints map[string][]byte
	// crlData is the Certificate Revocation List obtained from discovery server
	crl *x509.RevocationList
	// enableCRLChecking controls whether CRL checking is performed
	enableCRLChecking bool
	// mu protects access to trustedFingerprints map
	mu sync.RWMutex
}

// NewClientCertificateVerifier creates a new certificate verifier for clients
// caCertDER should be the discovery server's CA certificate in DER format (pre-shared)
func NewClientCertificateVerifier(caCert x509.Certificate) (*ClientCertificateVerifier, error) {
	return &ClientCertificateVerifier{
		caCert:              &caCert,
		trustedFingerprints: make(map[string][]byte),
		crl:                 nil,  // No CRL loaded initially
		enableCRLChecking:   true, // CRL checking enabled by default
	}, nil
}

// VerifyPeerCertificate verifies that a peer's certificate was signed by the trusted CA
func (cv *ClientCertificateVerifier) VerifyPeerCertificate(certDER []byte) (*x509.Certificate, error) {
	// Parse the peer certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer certificate: %w", err)
	}

	// Create a certificate pool with our trusted CA
	roots := x509.NewCertPool()
	roots.AddCert(cv.caCert)

	// Verify the certificate
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("certificate verification failed: %w", err)
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate expired")
	}

	// Check certificate revocation if CRL checking is enabled
	if cv.enableCRLChecking {
		revoked, err := cv.checkCertificateRevocation(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to check certificate revocation: %w", err)
		}
		if revoked {
			return nil, fmt.Errorf("certificate has been revoked")
		}
	}

	return cert, nil
}

// GenerateCertificateFingerprint creates a SHA-256 fingerprint of a certificate
func (cv *ClientCertificateVerifier) GenerateCertificateFingerprint(certDER []byte) ([]byte, error) {
	hash := sha256.Sum256(certDER)
	return hash[:], nil
}

// AddTrustedFingerprint adds a certificate fingerprint to the trusted cache
// This allows for efficient handshakes using only fingerprints
func (cv *ClientCertificateVerifier) AddTrustedFingerprint(fingerprint []byte, certDER []byte) error {
	// Verify the certificate first
	_, err := cv.VerifyPeerCertificate(certDER)
	if err != nil {
		return fmt.Errorf("cannot add untrusted certificate: %w", err)
	}

	// Add to trusted fingerprints cache
	fingerprintHex := hex.EncodeToString(fingerprint)
	cv.mu.Lock()
	cv.trustedFingerprints[fingerprintHex] = certDER
	cv.mu.Unlock()

	return nil
}

// VerifyHandshakeWithFingerprint verifies a handshake using a certificate fingerprint
// This is more efficient than sending full certificates in each handshake
func (cv *ClientCertificateVerifier) VerifyHandshakeWithFingerprint(
	handshakeData []byte,
	signature []byte,
	fingerprint []byte,
) (bool, error) {
	fingerprintHex := hex.EncodeToString(fingerprint)

	// Look up the certificate by fingerprint
	cv.mu.RLock()
	certDER, exists := cv.trustedFingerprints[fingerprintHex]
	cv.mu.RUnlock()

	if !exists {
		return false, fmt.Errorf("certificate with fingerprint %s not found in trusted cache", fingerprintHex)
	}

	// Parse the certificate to get the public key
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return false, fmt.Errorf("failed to parse cached certificate: %w", err)
	}

	// Get the public key from the certificate
	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("certificate does not contain an Ed25519 public key")
	}

	// Verify the signature
	return ed25519.Verify(pubKey, handshakeData, signature), nil
}

// GetTrustedFingerprints returns a copy of all trusted fingerprints
func (cv *ClientCertificateVerifier) GetTrustedFingerprints() map[string][]byte {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	result := make(map[string][]byte)
	for k, v := range cv.trustedFingerprints {
		cp := make([]byte, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result
}

// IsFingerprintTrusted checks if a fingerprint is in the trusted cache
func (cv *ClientCertificateVerifier) IsFingerprintTrusted(fingerprint []byte) bool {
	fingerprintHex := hex.EncodeToString(fingerprint)
	cv.mu.RLock()
	_, exists := cv.trustedFingerprints[fingerprintHex]
	cv.mu.RUnlock()
	return exists
}

// LoadCRL loads a Certificate Revocation List for checking certificate revocation status
func (cv *ClientCertificateVerifier) LoadCRL(crlData []byte) error {
	// Validate the CRL by parsing it
	parsedCRL, err := x509.ParseRevocationList(crlData)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Verify the CRL was signed by our trusted CA
	err = parsedCRL.CheckSignatureFrom(cv.caCert)
	if err != nil {
		return fmt.Errorf("CRL signature verification failed: %w", err)
	}

	// Check if CRL is still valid
	now := time.Now()
	if now.After(parsedCRL.NextUpdate) {
		return fmt.Errorf("CRL has expired")
	}

	// Store the CRL
	cv.crl = parsedCRL
	return nil
}

// EnableCRLChecking enables or disables CRL checking during certificate verification
func (cv *ClientCertificateVerifier) EnableCRLChecking(enable bool) {
	cv.enableCRLChecking = enable
}

// IsCRLCheckingEnabled returns whether CRL checking is currently enabled
func (cv *ClientCertificateVerifier) IsCRLCheckingEnabled() bool {
	return cv.enableCRLChecking
}

// HasCRL returns whether a CRL has been loaded
func (cv *ClientCertificateVerifier) HasCRL() bool {
	return cv.crl != nil
}

// checkCertificateRevocation checks if a certificate is revoked using the loaded CRL
func (cv *ClientCertificateVerifier) checkCertificateRevocation(cert *x509.Certificate) (bool, error) {
	cv.mu.RLock()
	crl := cv.crl
	enableChecking := cv.enableCRLChecking
	cv.mu.RUnlock()

	if !enableChecking || crl == nil {
		// CRL checking disabled or no CRL loaded
		return false, nil
	}

	// Check if CRL is still valid
	now := time.Now()
	if now.After(crl.NextUpdate) {
		cv.mu.Lock()
		cv.crl = nil // Clear expired CRL
		cv.mu.Unlock()
		return false, fmt.Errorf("CRL has expired")
	}
	// Check if certificate serial number is in the revoked list
	for _, revokedCert := range cv.crl.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

// GetCACertificateFingerprint returns the fingerprint of the trusted CA certificate
func (cv *ClientCertificateVerifier) GetCACertificateFingerprint() ([]byte, error) {
	return cv.GenerateCertificateFingerprint(cv.caCert.Raw)
}
