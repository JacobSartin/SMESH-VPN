package certs

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"testing"
	"uuid"
)

// TestCertificateArchitecture demonstrates the complete certificate architecture
// for SMESH-VPN where only the discovery server has a CA
func TestCertificateArchitecture(t *testing.T) {
	// Step 1: Create a Certificate Authority on the discovery server
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	caID, err := uuid.Parse(ca.ID)
	if err != nil {
		t.Fatalf("CA ID is not a valid UUID: %v", err)
	}
	if got := caID[6] >> 4; got != 7 {
		t.Fatalf("expected CA ID to be UUIDv7, got v%d", got)
	}

	t.Logf("✓ Discovery server CA created with ID: %s", ca.ID)

	// Step 2: Get the CA certificate for distribution to clients
	caCertDER, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	t.Logf("✓ CA certificate size: %d bytes", len(caCertDER))

	// Step 3: Simulate two clients that have the CA certificate pre-shared
	clientAVerifier, err := NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create client A verifier: %v", err)
	}

	clientBVerifier, err := NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create client B verifier: %v", err)
	}

	t.Logf("✓ Both clients have CA certificate and can verify peer certificates")

	// Step 4: Generate key pairs for both clients
	clientAPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("Failed to generate client A keys: %v", err)
	}
	clientBPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("Failed to generate client B keys: %v", err)
	}

	// Step 5: Discovery server issues certificates to approved clients
	clientACertDER, err := ca.IssueClientCertificate(clientAPriv.PublicKey(), "client-A")
	if err != nil {
		t.Fatalf("Failed to issue certificate for client A: %v", err)
	}

	clientBCertDER, err := ca.IssueClientCertificate(clientBPriv.PublicKey(), "client-B")
	if err != nil {
		t.Fatalf("Failed to issue certificate for client B: %v", err)
	}

	t.Logf("✓ Discovery server issued certificates:")
	t.Logf("  - Client A certificate: %d bytes", len(clientACertDER))
	t.Logf("  - Client B certificate: %d bytes", len(clientBCertDER))

	// Step 6: Clients verify each other's certificates using their CA verifier
	clientACert, err := clientBVerifier.VerifyPeerCertificate(clientACertDER)
	if err != nil {
		t.Fatalf("Client B failed to verify client A's certificate: %v", err)
	}

	clientBCert, err := clientAVerifier.VerifyPeerCertificate(clientBCertDER)
	if err != nil {
		t.Fatalf("Client A failed to verify client B's certificate: %v", err)
	}

	t.Logf("✓ Certificate verification successful:")
	t.Logf("  - Client A verified by Client B: %s", clientACert.Subject.CommonName)
	t.Logf("  - Client B verified by Client A: %s", clientBCert.Subject.CommonName)

	// Step 7: Test fingerprint-based handshake for efficiency
	clientAFingerprint, err := clientAVerifier.GenerateCertificateFingerprint(clientACertDER)
	if err != nil {
		t.Fatalf("Failed to generate client A fingerprint: %v", err)
	}

	clientBFingerprint, err := clientBVerifier.GenerateCertificateFingerprint(clientBCertDER)
	if err != nil {
		t.Fatalf("Failed to generate client B fingerprint: %v", err)
	}

	// Add to trusted fingerprint cache
	err = clientAVerifier.AddTrustedFingerprint(clientBFingerprint, clientBCertDER)
	if err != nil {
		t.Fatalf("Failed to add client B fingerprint to client A cache: %v", err)
	}

	err = clientBVerifier.AddTrustedFingerprint(clientAFingerprint, clientACertDER)
	if err != nil {
		t.Fatalf("Failed to add client A fingerprint to client B cache: %v", err)
	}

	t.Logf("✓ Fingerprint cache populated:")
	t.Logf("  - Client A fingerprint: %d bytes", len(clientAFingerprint))
	t.Logf("  - Client B fingerprint: %d bytes", len(clientBFingerprint))

	// Step 8: Simulate a handshake using fingerprints
	handshakeData := []byte("SMESH-VPN-HANDSHAKE-DATA")

	// Client A signs handshake data
	signatureA, err := clientAPriv.Sign(nil, handshakeData, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Failed to sign handshake: %v", err)
	}

	// Client B verifies the signature using client A's fingerprint
	valid, err := clientBVerifier.VerifyHandshakeWithFingerprint(handshakeData, signatureA, clientAFingerprint)
	if err != nil {
		t.Fatalf("Failed to verify handshake with fingerprint: %v", err)
	}

	if !valid {
		t.Fatalf("Handshake signature verification failed")
	}

	t.Logf("✓ Fingerprint-based handshake successful")

	// Step 9: Calculate total handshake size with different approaches
	mtuLimit := 1500
	mlkemCiphertextSize := 1088
	x25519PubKeySize := 32
	overheadEstimate := 100

	// Full certificate handshake
	fullCertSize := mlkemCiphertextSize + len(clientACertDER) + x25519PubKeySize + len(signatureA) + overheadEstimate

	// Fingerprint-based handshake
	fingerprintSize := mlkemCiphertextSize + len(clientAFingerprint) + x25519PubKeySize + len(signatureA) + overheadEstimate

	t.Logf("\n📊 Handshake Size Analysis:")
	t.Logf("  - Full certificate handshake: %d bytes", fullCertSize)
	t.Logf("  - Fingerprint-based handshake: %d bytes", fingerprintSize)
	t.Logf("  - Size savings: %d bytes", fullCertSize-fingerprintSize)
	t.Logf("  - MTU limit: %d bytes", mtuLimit)

	if fullCertSize <= mtuLimit {
		t.Logf("  ✓ Full certificate handshake fits in MTU")
	} else {
		t.Logf("  ✗ Full certificate handshake exceeds MTU by %d bytes", fullCertSize-mtuLimit)
	}

	if fingerprintSize <= mtuLimit {
		t.Logf("  ✓ Fingerprint handshake fits in MTU")
	} else {
		t.Logf("  ✗ Fingerprint handshake exceeds MTU by %d bytes", fingerprintSize-mtuLimit)
	} // Step 10: Verify CA certificate validation on the server side
	// Parse certificates first
	certA, err := x509.ParseCertificate(clientACertDER)
	if err != nil {
		t.Fatalf("Failed to parse client A certificate: %v", err)
	}
	certB, err := x509.ParseCertificate(clientBCertDER)
	if err != nil {
		t.Fatalf("Failed to parse client B certificate: %v", err)
	}

	isValidClientA, err := ca.ValidateClientCertificate(certA)
	if err != nil {
		t.Fatalf("CA failed to validate client A certificate: %v", err)
	}
	if !isValidClientA {
		t.Fatalf("Client A certificate validation failed")
	}

	isValidClientB, err := ca.ValidateClientCertificate(certB)
	if err != nil {
		t.Fatalf("CA failed to validate client B certificate: %v", err)
	}
	if !isValidClientB {
		t.Fatalf("Client B certificate validation failed")
	}

	t.Logf("✓ CA validation successful:")
	t.Logf("  - Client A: %s", certA.Subject.CommonName)
	t.Logf("  - Client B: %s", certB.Subject.CommonName)
}

// TestInvalidCertificateRejection tests that invalid certificates are properly rejected
func TestInvalidCertificateRejection(t *testing.T) {
	// Create a CA
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Get CA certificate
	caCertDER, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create client verifier
	verifier, err := NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}
	// Create a self-signed certificate (not signed by our CA)
	selfSignedPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("Failed to generate self-signed keys: %v", err)
	}

	// This would be a certificate from a different CA or self-signed
	// For this test, we'll create an invalid certificate by trying to verify
	// a certificate that wasn't issued by our CA
	invalidCertData := []byte("invalid-certificate-data")

	// This should fail
	_, err = verifier.VerifyPeerCertificate(invalidCertData)
	if err == nil {
		t.Errorf("Expected verification to fail for invalid certificate, but it succeeded")
	}

	t.Logf("✓ Invalid certificate properly rejected: %v", err)

	// Test with a legitimate certificate from our CA
	validPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("Failed to generate valid keys: %v", err)
	}

	validCertDER, err := ca.IssueClientCertificate(validPriv.PublicKey(), "valid-client")
	if err != nil {
		t.Fatalf("Failed to issue valid certificate: %v", err)
	}

	// This should succeed
	validCert, err := verifier.VerifyPeerCertificate(validCertDER)
	if err != nil {
		t.Fatalf("Expected verification to succeed for valid certificate: %v", err)
	}

	t.Logf("✓ Valid certificate properly accepted: %s", validCert.Subject.CommonName)

	// Test signature verification with wrong private key
	handshakeData := []byte("test-handshake")
	wrongSignature, err := selfSignedPriv.Sign(nil, handshakeData, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Failed to create wrong signature: %v", err)
	}

	fingerprint, err := verifier.GenerateCertificateFingerprint(validCertDER)
	if err != nil {
		t.Fatalf("Failed to generate fingerprint: %v", err)
	}

	err = verifier.AddTrustedFingerprint(fingerprint, validCertDER)
	if err != nil {
		t.Fatalf("Failed to add fingerprint: %v", err)
	}

	// This should fail because signature is from wrong key
	valid, err := verifier.VerifyHandshakeWithFingerprint(handshakeData, wrongSignature, fingerprint)
	if err != nil {
		t.Fatalf("Unexpected error in signature verification: %v", err)
	}

	if valid {
		t.Errorf("Expected signature verification to fail with wrong private key")
	}

	t.Logf("✓ Invalid signature properly rejected")
}
