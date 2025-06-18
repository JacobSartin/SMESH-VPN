package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// TestCertificateAuthorityWithCRL tests basic CRL functionality
func TestCertificateAuthorityWithCRL(t *testing.T) {
	// Create a new Certificate Authority
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Get CRL manager
	crlManager := ca.GetCRLManager()

	// Generate a client key pair
	clientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	// Issue a certificate for the client
	clientID := "test-client-1"
	certDER, err := ca.IssueClientCertificate(clientPub, clientID)
	if err != nil {
		t.Fatalf("Failed to issue client certificate: %v", err)
	}

	// Validate the certificate initially (should pass)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	isValid, err := ca.ValidateClientCertificate(cert)
	if err != nil {
		t.Fatalf("Failed to validate certificate: %v", err)
	}

	if !isValid {
		t.Fatal("Certificate validation failed")
	}

	// Check that the certificate is not revoked initially
	isRevoked, err := crlManager.CheckCertificateRevocation(cert)
	if err != nil {
		t.Fatalf("Failed to check certificate revocation: %v", err)
	}

	if isRevoked {
		t.Fatal("Certificate should not be revoked initially")
	}

	// Get initial revoked certificates list (should be empty)
	revokedCerts := crlManager.ListRevokedCertificates()
	if len(revokedCerts) != 0 {
		t.Fatalf("Expected 0 revoked certificates, got %d", len(revokedCerts))
	}

	// Revoke the certificate using the new CA-passing approach
	err = ca.RevokeCertificate(clientID, 0) // 0 = unspecified reason
	if err != nil {
		t.Fatalf("Failed to revoke certificate: %v", err)
	}

	// Check that the certificate is now revoked
	isRevoked, err = crlManager.CheckCertificateRevocation(cert)
	if err != nil {
		t.Fatalf("Failed to check certificate revocation after revocation: %v", err)
	}

	if !isRevoked {
		t.Fatal("Certificate should be revoked after calling RevokeCertificate")
	}

	// Validate the certificate again (should fail)
	isValid, err = ca.ValidateClientCertificate(cert)
	if err == nil && isValid {
		t.Fatal("Certificate validation should fail for revoked certificate")
	}

	// Get updated revoked certificates list
	revokedCerts = crlManager.ListRevokedCertificates()
	if len(revokedCerts) != 1 {
		t.Fatalf("Expected 1 revoked certificate, got %d", len(revokedCerts))
	}

	// Test CRL export
	crlBytes, err := ca.GetCRL()
	if err != nil {
		t.Fatalf("Failed to get CRL: %v", err)
	}

	if len(crlBytes) == 0 {
		t.Fatal("CRL bytes should not be empty")
	}

	// Test CRL validation by parsing
	_, err = x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("Failed to parse exported CRL: %v", err)
	}
}

// TestRevokeCertificateBySerial tests revoking certificates by serial number
func TestRevokeCertificateBySerial(t *testing.T) {
	// Create a new Certificate Authority
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	crlManager := ca.GetCRLManager()

	// Generate multiple client certificates
	clientIDs := []string{"client-1", "client-2", "client-3"}
	var certificates []*x509.Certificate

	for _, clientID := range clientIDs {
		clientPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate client key pair: %v", err)
		}

		certDER, err := ca.IssueClientCertificate(clientPub, clientID)
		if err != nil {
			t.Fatalf("Failed to issue client certificate: %v", err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		certificates = append(certificates, cert)
	}

	// Revoke the second certificate by serial number
	targetSerial := certificates[1].SerialNumber
	err = ca.RevokeCertificateBySerial(targetSerial, 1) // 1 = key compromise
	if err != nil {
		t.Fatalf("Failed to revoke certificate by serial: %v", err)
	}

	// Check that the certificate is revoked
	isRevoked, err := crlManager.CheckCertificateRevocation(certificates[1])
	if err != nil {
		t.Fatalf("Failed to check certificate revocation: %v", err)
	}

	if !isRevoked {
		t.Fatal("Certificate should be revoked after calling RevokeCertificateBySerial")
	}

	// Check that other certificates are not revoked
	for i, cert := range certificates {
		if i == 1 {
			continue // Skip the revoked certificate
		}

		isRevoked, err := crlManager.CheckCertificateRevocation(cert)
		if err != nil {
			t.Fatalf("Failed to check certificate revocation for cert %d: %v", i, err)
		}

		if isRevoked {
			t.Fatalf("Certificate %d should not be revoked", i)
		}
	}

	// Test revoking non-existent certificate
	nonExistentSerial := big.NewInt(99999)
	err = ca.RevokeCertificateBySerial(nonExistentSerial, 0)
	if err == nil {
		t.Fatal("Expected error when revoking non-existent certificate")
	}

	if err != ErrCertificateNotFound {
		t.Fatalf("Expected ErrCertificateNotFound, got: %v", err)
	}
}

// TestCRLValidityAndExpiration tests CRL validity periods and expiration
func TestCRLValidityAndExpiration(t *testing.T) {
	// Create a CA with short CRL validity period for testing
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	crlManager := ca.GetCRLManager()

	// Generate and issue a client certificate
	clientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	clientID := "test-client"
	certDER, err := ca.IssueClientCertificate(clientPub, clientID)
	if err != nil {
		t.Fatalf("Failed to issue client certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Revoke the certificate to create a CRL
	err = ca.RevokeCertificate(clientID, 0)
	if err != nil {
		t.Fatalf("Failed to revoke certificate: %v", err)
	}

	// Check that CRL is valid
	if !crlManager.IsValidCRL() {
		t.Fatal("CRL should be valid after creation")
	}

	// Get next update time
	nextUpdate := crlManager.GetNextCRLUpdateTime()
	if nextUpdate.IsZero() {
		t.Fatal("Next update time should not be zero")
	}

	if !nextUpdate.After(time.Now()) {
		t.Fatal("Next update time should be in the future")
	}

	// Test CRL export and validation
	crlBytes, err := ca.GetCRL()
	if err != nil {
		t.Fatalf("Failed to get CRL: %v", err)
	}

	// Validate CRL signature
	err = crlManager.ValidateCRLSignature(crlBytes, ca.GetCertificateTemplate())
	if err != nil {
		t.Fatalf("Failed to validate CRL signature: %v", err)
	}

	// Test external CRL checking
	isRevoked, err := crlManager.CheckCertificateRevocationByCRL(crlBytes, cert)
	if err != nil {
		t.Fatalf("Failed to check certificate revocation by external CRL: %v", err)
	}

	if !isRevoked {
		t.Fatal("Certificate should be revoked according to external CRL")
	}
}

// TestMultipleCertificateRevocations tests handling multiple revoked certificates
func TestMultipleCertificateRevocations(t *testing.T) {
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	crlManager := ca.GetCRLManager()

	// Issue multiple certificates
	numCerts := 5
	clientIDs := make([]string, numCerts)
	certificates := make([]*x509.Certificate, numCerts)

	for i := 0; i < numCerts; i++ {
		clientPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate client key pair: %v", err)
		}

		clientID := fmt.Sprintf("client-%d", i)
		clientIDs[i] = clientID

		certDER, err := ca.IssueClientCertificate(clientPub, clientID)
		if err != nil {
			t.Fatalf("Failed to issue client certificate: %v", err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		certificates[i] = cert
	}

	// Revoke every other certificate
	revokedIndices := []int{0, 2, 4}
	for _, idx := range revokedIndices {
		err := ca.RevokeCertificate(clientIDs[idx], 0)
		if err != nil {
			t.Fatalf("Failed to revoke certificate %d: %v", idx, err)
		}
	}

	// Check revocation status
	for i, cert := range certificates {
		isRevoked, err := crlManager.CheckCertificateRevocation(cert)
		if err != nil {
			t.Fatalf("Failed to check certificate revocation for cert %d: %v", i, err)
		}

		shouldBeRevoked := false
		for _, revokedIdx := range revokedIndices {
			if i == revokedIdx {
				shouldBeRevoked = true
				break
			}
		}

		if isRevoked != shouldBeRevoked {
			t.Fatalf("Certificate %d revocation status mismatch: got %v, expected %v", i, isRevoked, shouldBeRevoked)
		}
	}

	// Check revoked certificates list
	revokedCerts := crlManager.ListRevokedCertificates()
	if len(revokedCerts) != len(revokedIndices) {
		t.Fatalf("Expected %d revoked certificates, got %d", len(revokedIndices), len(revokedCerts))
	}

	// Test filtering by reason code
	revokedByReason := crlManager.GetRevokedCertificatesByReason(0)
	if len(revokedByReason) != len(revokedIndices) {
		t.Fatalf("Expected %d revoked certificates with reason 0, got %d", len(revokedIndices), len(revokedByReason))
	}
}
