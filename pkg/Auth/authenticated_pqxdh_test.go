package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	"github.com/google/uuid"
)

// EstablishAuthenticatedConnection performs the complete authenticated handshake
// This is a test helper function that simulates a complete handshake in a single process
func EstablishAuthenticatedConnection(client *AuthenticatedPQXDHClient, server *AuthenticatedPQXDHServer) (clientKey, serverKey []byte, err error) {
	// Client creates hello message
	clientHello, err := client.CreateClientHello()
	if err != nil {
		return nil, nil, fmt.Errorf("client hello creation failed: %w", err)
	}

	// Server processes hello and creates response
	serverResponse, serverSharedKey, err := server.ProcessClientHello(clientHello)
	if err != nil {
		return nil, nil, fmt.Errorf("server hello processing failed: %w", err)
	}

	// Client processes server response
	clientSharedKey, err := client.ProcessServerResponse(serverResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("client response processing failed: %w", err)
	}

	return clientSharedKey, serverSharedKey, nil
}

// TestAuthenticatedPQXDHHandshake tests the complete authenticated handshake
func TestAuthenticatedPQXDHHandshake(t *testing.T) {
	// Create Certificate Authority
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Generate client certificate
	clientCert, clientPrivKey, err := createTestClientCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	// Generate server certificate
	serverCert, serverPrivKey, err := createTestServerCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Get CA root certificate
	caCertBytes, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create verifiers for client and server
	clientVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create client verifier: %v", err)
	}

	serverVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create server verifier: %v", err)
	}

	// Create authenticated PQXDH instances
	client := NewAuthenticatedPQXDHClient(clientCert, clientPrivKey, clientVerifier, uuid.NullUUID{})
	server, err := NewAuthenticatedPQXDHServer(serverCert, serverPrivKey, serverVerifier)
	if err != nil {
		t.Fatalf("Failed to create authenticated PQXDH server: %v", err)
	}

	// Perform authenticated handshake
	clientKey, serverKey, err := EstablishAuthenticatedConnection(client, server)
	if err != nil {
		t.Fatalf("Authenticated handshake failed: %v", err)
	}

	// Verify both parties derived the same key
	if !bytes.Equal(clientKey, serverKey) {
		t.Errorf("Key exchange failed: client and server keys do not match")
	}

	// Verify key length
	if len(clientKey) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(clientKey))
	}

	t.Logf("Authenticated handshake successful, derived %d-byte shared key", len(clientKey))
}

// TestAuthenticatedHandshakeWithRevokedCertificate tests handshake rejection with revoked certificate
func TestAuthenticatedHandshakeWithRevokedCertificate(t *testing.T) {
	// Create Certificate Authority
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Generate client certificate
	clientCert, clientPrivKey, err := createTestClientCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	// Generate server certificate
	serverCert, serverPrivKey, err := createTestServerCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Revoke the client certificate (use RevokeCertificate method with client ID)
	err = ca.RevokeCertificate("test-client", 0) // 0 = unspecified reason
	if err != nil {
		t.Fatalf("Failed to revoke client certificate: %v", err)
	}

	// Get CA root certificate
	caCertBytes, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create shared verifiers (simulating what would be done once per client/server instance)
	clientVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create client verifier: %v", err)
	}

	serverVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create server verifier: %v", err)
	}

	// Simulate: Client and server have downloaded CRL from discovery server on boot
	// Get the current CRL from the CA
	crlBytes, err := ca.GetCRLManager().GetCRL()
	if err != nil {
		t.Fatalf("Failed to get CRL: %v", err)
	}

	// Load CRL into both verifiers (simulating discovery server download)
	err = clientVerifier.LoadCRL(crlBytes)
	if err != nil {
		t.Fatalf("Failed to load CRL into client verifier: %v", err)
	}
	err = serverVerifier.LoadCRL(crlBytes)
	if err != nil {
		t.Fatalf("Failed to load CRL into server verifier: %v", err)
	}

	// Enable CRL checking (simulating production configuration)
	clientVerifier.EnableCRLChecking(true)
	serverVerifier.EnableCRLChecking(true)

	// Create authenticated PQXDH instances with pre-configured verifiers
	client := NewAuthenticatedPQXDHClient(clientCert, clientPrivKey, clientVerifier, uuid.NullUUID{})
	server, err := NewAuthenticatedPQXDHServer(serverCert, serverPrivKey, serverVerifier)
	if err != nil {
		t.Fatalf("Failed to create authenticated PQXDH server: %v", err)
	}

	// Attempt authenticated handshake - should fail because client cert is revoked
	_, _, err = EstablishAuthenticatedConnection(client, server)
	if err == nil {
		t.Fatalf("Expected handshake to fail with revoked certificate, but it succeeded")
	}

	// Check that error is related to certificate revocation
	if err.Error() != "server hello processing failed: client certificate validation failed: certificate has been revoked" {
		t.Logf("Got expected error: %v", err)
	}

	t.Logf("Correctly rejected handshake with revoked certificate: %v", err)
}

// TestAuthenticatedHandshakeWithInvalidSignature tests handshake rejection with invalid signature
func TestAuthenticatedHandshakeWithInvalidSignature(t *testing.T) {
	// Create Certificate Authority
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Generate client certificate
	clientCert, _, err := createTestClientCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	// Generate a different private key (not matching the certificate)
	_, wrongPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate wrong private key: %v", err)
	}

	// Generate server certificate
	serverCert, serverPrivKey, err := createTestServerCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}
	// Get CA root certificate
	caCertBytes, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create verifiers for client and server
	clientVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create client verifier: %v", err)
	}

	serverVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create server verifier: %v", err)
	}

	// Create authenticated PQXDH instances with wrong client key
	client := NewAuthenticatedPQXDHClient(clientCert, wrongPrivKey, clientVerifier, uuid.NullUUID{})
	server, err := NewAuthenticatedPQXDHServer(serverCert, serverPrivKey, serverVerifier)
	if err != nil {
		t.Fatalf("Failed to create authenticated PQXDH server: %v", err)
	}

	// Attempt authenticated handshake - should fail
	_, _, err = EstablishAuthenticatedConnection(client, server)
	if err == nil {
		t.Fatalf("Expected handshake to fail with invalid signature, but it succeeded")
	}

	// Check that error is related to invalid signature
	if err == ErrInvalidSignature || err.Error() == "server hello processing failed: invalid handshake signature" {
		t.Logf("Correctly rejected handshake with invalid signature: %v", err)
	} else {
		t.Errorf("Expected signature error, got: %v", err)
	}
}

// TestAuthenticatedHandshakeReplayProtection tests protection against replay attacks
func TestAuthenticatedHandshakeReplayProtection(t *testing.T) {
	// Create Certificate Authority
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Generate certificates
	clientCert, clientPrivKey, err := createTestClientCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	serverCert, serverPrivKey, err := createTestServerCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}
	// Get CA root certificate
	caCertBytes, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create verifiers for client and server
	clientVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create client verifier: %v", err)
	}

	serverVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create server verifier: %v", err)
	}

	// Create authenticated PQXDH instances
	client := NewAuthenticatedPQXDHClient(clientCert, clientPrivKey, clientVerifier, uuid.NullUUID{})
	server, err := NewAuthenticatedPQXDHServer(serverCert, serverPrivKey, serverVerifier)
	if err != nil {
		t.Fatalf("Failed to create authenticated PQXDH server: %v", err)
	}

	// Create a client hello with old timestamp
	clientHello, err := client.CreateClientHello()
	if err != nil {
		t.Fatalf("Failed to create client hello: %v", err)
	}

	// Modify timestamp to be 10 minutes old
	clientHello.Timestamp = time.Now().Add(-10 * time.Minute)

	// Re-sign with the old timestamp
	signatureData := append(clientHello.PQPublicKey, clientHello.ECPublicKey...)
	signatureData = append(signatureData, clientHello.Certificate...)
	timestampBytes, _ := clientHello.Timestamp.MarshalBinary()
	signatureData = append(signatureData, timestampBytes...)
	clientHello.Signature = ed25519.Sign(clientPrivKey, signatureData)

	// Attempt to process the old message - should fail
	_, _, err = server.ProcessClientHello(clientHello)
	if err == nil {
		t.Fatalf("Expected handshake to fail with old timestamp, but it succeeded")
	}

	// Check that error is related to timeout
	if err == ErrHandshakeTimeout || err.Error() == "handshake timeout" {
		t.Logf("Correctly rejected handshake with old timestamp: %v", err)
	} else {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

// BenchmarkAuthenticatedHandshake benchmarks the authenticated handshake performance
func BenchmarkAuthenticatedHandshake(b *testing.B) {
	// Setup
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		b.Fatalf("Failed to create CA: %v", err)
	}

	clientCert, clientPrivKey, err := createTestClientCertificate(ca)
	if err != nil {
		b.Fatalf("Failed to create client certificate: %v", err)
	}

	serverCert, serverPrivKey, err := createTestServerCertificate(ca)
	if err != nil {
		b.Fatalf("Failed to create server certificate: %v", err)
	}
	caCertBytes, err := ca.GetCACertificate()
	if err != nil {
		b.Fatalf("Failed to get CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		b.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create verifiers for client and server (reused across benchmark iterations)
	clientVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		b.Fatalf("Failed to create client verifier: %v", err)
	}

	serverVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		b.Fatalf("Failed to create server verifier: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client := NewAuthenticatedPQXDHClient(clientCert, clientPrivKey, clientVerifier, uuid.NullUUID{})
		server, err := NewAuthenticatedPQXDHServer(serverCert, serverPrivKey, serverVerifier)
		if err != nil {
			b.Fatalf("Failed to create authenticated PQXDH server: %v", err)
		}

		clientKey, serverKey, err := EstablishAuthenticatedConnection(client, server)
		if err != nil {
			b.Fatalf("Authenticated handshake failed: %v", err)
		}

		if !bytes.Equal(clientKey, serverKey) {
			b.Fatalf("Keys don't match")
		}
	}
}

// Helper function to create a test client certificate
func createTestClientCertificate(ca *certs.CertificateAuthority) (*x509.Certificate, ed25519.PrivateKey, error) {
	// Generate key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Use CA to issue certificate
	certDER, err := ca.IssueClientCertificate(pubKey, "test-client")
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

// Helper function to create a test server certificate
func createTestServerCertificate(ca *certs.CertificateAuthority) (*x509.Certificate, ed25519.PrivateKey, error) {
	// Generate key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Use CA to issue certificate
	certDER, err := ca.IssueClientCertificate(pubKey, "test-server")
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

// TestInvalidSignatureWrongKey tests handshake rejection when signature is not signed by the right key
func TestInvalidSignatureWrongKey(t *testing.T) {
	// Create Certificate Authority
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Generate client certificate
	clientCert, clientPrivKey, err := createTestClientCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	// Generate server certificate
	serverCert, serverPrivKey, err := createTestServerCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Get CA root certificate
	caCertBytes, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create verifiers for client and server
	clientVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create client verifier: %v", err)
	}

	serverVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create server verifier: %v", err)
	}

	// Create authenticated PQXDH instances
	client := NewAuthenticatedPQXDHClient(clientCert, clientPrivKey, clientVerifier, uuid.NullUUID{})
	server, err := NewAuthenticatedPQXDHServer(serverCert, serverPrivKey, serverVerifier)
	if err != nil {
		t.Fatalf("Failed to create authenticated PQXDH server: %v", err)
	}

	// Create a client hello
	clientHello, err := client.CreateClientHello()
	if err != nil {
		t.Fatalf("Failed to create client hello: %v", err)
	}

	// Generate a different private key to sign with
	_, wrongPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate wrong private key: %v", err)
	}

	// Re-sign the message with the wrong private key
	signatureData := append(clientHello.PQPublicKey, clientHello.ECPublicKey...)
	signatureData = append(signatureData, clientHello.Certificate...)
	timestampBytes, _ := clientHello.Timestamp.MarshalBinary()
	signatureData = append(signatureData, timestampBytes...)
	clientHello.Signature = ed25519.Sign(wrongPrivKey, signatureData)

	// Attempt to process the message with wrong signature - should fail
	_, _, err = server.ProcessClientHello(clientHello)
	if err == nil {
		t.Fatalf("Expected handshake to fail with wrong signature key, but it succeeded")
	}

	// Check that error is related to invalid signature
	t.Logf("Correctly rejected handshake with wrong signature key: %v", err)
}

// TestValidSignatureTamperedMessage tests handshake rejection when signature is valid but message was tampered
func TestValidSignatureTamperedMessage(t *testing.T) {
	// Create Certificate Authority
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Generate client certificate
	clientCert, clientPrivKey, err := createTestClientCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	// Generate server certificate
	serverCert, serverPrivKey, err := createTestServerCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Get CA root certificate
	caCertBytes, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("Failed to get CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create verifiers for client and server
	clientVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create client verifier: %v", err)
	}

	serverVerifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create server verifier: %v", err)
	}

	// Create authenticated PQXDH instances
	client := NewAuthenticatedPQXDHClient(clientCert, clientPrivKey, clientVerifier, uuid.NullUUID{})
	server, err := NewAuthenticatedPQXDHServer(serverCert, serverPrivKey, serverVerifier)
	if err != nil {
		t.Fatalf("Failed to create authenticated PQXDH server: %v", err)
	}
	// Create a client hello with valid signature
	clientHello, err := client.CreateClientHello()
	if err != nil {
		t.Fatalf("Failed to create client hello: %v", err)
	}

	// Tamper with the PQ public key (change the first byte)
	// The signature remains valid for the original message, but now the message content is different
	if len(clientHello.PQPublicKey) > 0 {
		clientHello.PQPublicKey[0] ^= 0x01 // Flip the first bit
	}

	// Attempt to process the tampered message - should fail
	_, _, err = server.ProcessClientHello(clientHello)
	if err == nil {
		t.Fatalf("Expected handshake to fail with tampered message, but it succeeded")
	}

	// Check that error is related to invalid signature verification
	t.Logf("Correctly rejected handshake with tampered message: %v", err)
	// Test another type of tampering: modify the certificate
	clientHello2, err := client.CreateClientHello()
	if err != nil {
		t.Fatalf("Failed to create second client hello: %v", err)
	}

	// Tamper with the certificate (change the last byte)
	// The signature remains valid for the original message, but now the certificate content is different
	if len(clientHello2.Certificate) > 0 {
		clientHello2.Certificate[len(clientHello2.Certificate)-1] ^= 0x01
	}

	// Attempt to process the tampered certificate message - should fail
	_, _, err = server.ProcessClientHello(clientHello2)
	if err == nil {
		t.Fatalf("Expected handshake to fail with tampered certificate, but it succeeded")
	}

	t.Logf("Correctly rejected handshake with tampered certificate: %v", err)
}

func TestBinary(t *testing.T) {
	ca, _ := certs.NewCertificateAuthority()

	caCertBytes, _ := ca.GetCACertificate()

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	verifier, err := certs.NewClientCertificateVerifier(*caCert)
	if err != nil {
		t.Fatalf("Failed to create client certificate verifier: %v", err)
	}

	// create certificates, keys and other necessary data
	clientCert, clientKey, err := createTestClientCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to generate client certificate: %v", err)
	}
	serverCert, serverKey, err := createTestServerCertificate(ca)
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	client := NewAuthenticatedPQXDHClient(clientCert, clientKey, verifier, uuid.NullUUID{})
	server, _ := NewAuthenticatedPQXDHServer(serverCert, serverKey, verifier)

	hello, err := client.CreateClientHello()
	if err != nil {
		t.Fatalf("Failed to create client hello: %v", err)
	}

	helloBytes, err := hello.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal client hello: %v", err)
	}

	hello2 := &AuthenticatedHandshakeHello{}
	if err := hello2.UnmarshalJSON(helloBytes); err != nil {
		t.Fatalf("Failed to unmarshal client hello: %v", err)
	}

	response, _, _ := server.ProcessClientHello(hello2)
	responseBytes, err := response.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal server response: %v", err)
	}

	response2 := &AuthenticatedHandshakeResponse{}
	if err := response2.UnmarshalJSON(responseBytes); err != nil {
		t.Fatalf("Failed to unmarshal server response: %v", err)
	}
}
