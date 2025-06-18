package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// CRLManager handles Certificate Revocation List operations independently
type CRLManager struct {
	revokedCertificates map[string]x509.RevocationListEntry // Map of clientID to CRL entry
	currentCRL          *x509.RevocationList                // Current CRL
	crlNumber           *big.Int
	crlValidityPeriod   time.Duration // How long a CRL is valid
	mu                  sync.RWMutex  // Protects access to revokedCertificates map
}

// NewCRLManager creates a new independent CRL manager
func NewCRLManager(validityPeriod time.Duration) *CRLManager {
	return &CRLManager{
		revokedCertificates: make(map[string]x509.RevocationListEntry),
		crlNumber:           big.NewInt(1),
		crlValidityPeriod:   validityPeriod,
	}
}

// RevokeCertificate marks a certificate as revoked and updates the CRL
func (crl *CRLManager) RevokeCertificate(clientID string, reasonCode int, ca *CertificateAuthority) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Find the certificate for this client
	cert, exists := ca.Certificates[clientID]
	if !exists {
		return ErrCertificateNotFound
	}

	// Revoke the certificate by adding it to the CRL
	entry := x509.RevocationListEntry{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now(),
		ReasonCode:     reasonCode,
	}

	crl.mu.Lock()
	crl.revokedCertificates[clientID] = entry
	crl.mu.Unlock()

	// Update the current CRL
	if err := crl.UpdateCRL(ca.Certificate, ca.PrivateKey); err != nil {
		return fmt.Errorf("failed to update CRL: %w", err)
	}

	// Remove the certificate from the active certificates
	delete(ca.Certificates, clientID)
	return nil
}

// RevokeCertificateBySerial revokes a certificate by its serial number
func (crl *CRLManager) RevokeCertificateBySerial(serialNumber *big.Int, reasonCode int, ca *CertificateAuthority) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Find the client ID for this serial number
	var clientID string
	var found bool
	for id, cert := range ca.Certificates {
		if cert.SerialNumber.Cmp(serialNumber) == 0 {
			clientID = id
			found = true
			break
		}
	}

	if !found {
		return ErrCertificateNotFound
	}
	// Revoke the certificate
	entry := x509.RevocationListEntry{
		SerialNumber:   serialNumber,
		RevocationTime: time.Now(),
		ReasonCode:     reasonCode,
	}

	crl.mu.Lock()
	crl.revokedCertificates[clientID] = entry
	crl.mu.Unlock()

	// Update the current CRL
	if err := crl.UpdateCRL(ca.Certificate, ca.PrivateKey); err != nil {
		return fmt.Errorf("failed to update CRL: %w", err)
	}

	// Remove the certificate from the active certificates
	delete(ca.Certificates, clientID)
	return nil
}

// UpdateCRL generates a new CRL and updates the currentCRL field
func (crl *CRLManager) UpdateCRL(caCert *x509.Certificate, caPrivKey crypto.Signer) error {
	crl.mu.Lock()
	defer crl.mu.Unlock()

	now := time.Now()
	nextUpdate := now.Add(crl.crlValidityPeriod)

	// Build revoked certificate list using the new format
	var revokedCerts []x509.RevocationListEntry
	for _, entry := range crl.revokedCertificates {
		revokedCerts = append(revokedCerts, entry)
	}

	// Create CRL template using the new format
	crlTemplate := &x509.RevocationList{
		Number:                    crl.crlNumber,
		ThisUpdate:                now,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: revokedCerts,
	}

	// Create and sign the CRL
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caPrivKey)
	if err != nil {
		return fmt.Errorf("failed to create CRL: %w", err)
	}

	// Parse the CRL back
	parsedCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	crl.currentCRL = parsedCRL
	crl.crlNumber = new(big.Int).Add(crl.crlNumber, big.NewInt(1))
	return nil
}

// GetCRL returns the current CRL in DER format
func (crl *CRLManager) GetCRL() ([]byte, error) {
	crl.mu.RLock()
	defer crl.mu.RUnlock()

	if crl.currentCRL == nil {
		return nil, fmt.Errorf("no CRL available")
	}

	return crl.currentCRL.Raw, nil
}

// CheckCertificateRevocation checks if a certificate is revoked using the current CRL
func (crl *CRLManager) CheckCertificateRevocation(cert *x509.Certificate) (bool, error) {
	crl.mu.RLock()
	defer crl.mu.RUnlock()

	if crl.currentCRL == nil {
		// No CRL available, consider certificate valid
		return false, nil
	}

	// Check if certificate serial number is in the revoked list
	for _, revokedCert := range crl.currentCRL.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

// CheckCertificateRevocationByCRL checks if a certificate is revoked using external CRL data
func (crl *CRLManager) CheckCertificateRevocationByCRL(crlData []byte, cert *x509.Certificate) (bool, error) {
	// Parse the CRL
	parsedCRL, err := x509.ParseRevocationList(crlData)
	if err != nil {
		return false, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Check if CRL is still valid
	now := time.Now()
	if now.After(parsedCRL.NextUpdate) {
		return false, fmt.Errorf("CRL has expired")
	}

	// Check if certificate serial number is in the revoked list
	for _, revokedCert := range parsedCRL.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

// ValidateCRLSignature verifies that a CRL was signed by the given CA
func (crl *CRLManager) ValidateCRLSignature(crlData []byte, caCert *x509.Certificate) error {
	// Parse the CRL
	parsedCRL, err := x509.ParseRevocationList(crlData)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Verify the CRL signature using the CA certificate
	err = parsedCRL.CheckSignatureFrom(caCert)
	if err != nil {
		return fmt.Errorf("CRL signature verification failed: %w", err)
	}

	return nil
}

// ListRevokedCertificates returns a list of all revoked certificates
func (crl *CRLManager) ListRevokedCertificates() map[string]x509.RevocationListEntry {
	crl.mu.RLock()
	defer crl.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]x509.RevocationListEntry)
	for k, v := range crl.revokedCertificates {
		result[k] = v
	}
	return result
}

// GetRevokedCertificatesByReason returns revoked certificates filtered by reason code
func (crl *CRLManager) GetRevokedCertificatesByReason(reasonCode int) map[string]x509.RevocationListEntry {
	crl.mu.RLock()
	defer crl.mu.RUnlock()

	result := make(map[string]x509.RevocationListEntry)
	for clientID, entry := range crl.revokedCertificates {
		if entry.ReasonCode == reasonCode {
			result[clientID] = entry
		}
	}
	return result
}

// GetNextCRLUpdateTime returns when the next CRL update is scheduled
func (crl *CRLManager) GetNextCRLUpdateTime() time.Time {
	crl.mu.RLock()
	defer crl.mu.RUnlock()

	if crl.currentCRL == nil {
		return time.Time{}
	}

	return crl.currentCRL.NextUpdate
}

// IsValidCRL checks if the current CRL is still valid (not expired)
func (crl *CRLManager) IsValidCRL() bool {
	crl.mu.RLock()
	defer crl.mu.RUnlock()

	if crl.currentCRL == nil {
		return false
	}

	return time.Now().Before(crl.currentCRL.NextUpdate)
}
