// Package auth provides certificate-authenticated PQXDH key exchange
// This integrates the existing Certificate Authority system with PQXDH handshakes
package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	pqxdh "github.com/JacobSartin/SMESH-VPN/pkg/PQXDH"
	"github.com/google/uuid"
)

// Errors for authenticated key exchange
var (
	ErrInvalidCertificate            = errors.New("invalid certificate")
	ErrCertificateRevoked            = errors.New("certificate revoked")
	ErrCertificateExpired            = errors.New("certificate expired")
	ErrCertificateVerificationFailed = errors.New("certificate verification failed")
	ErrHandshakeTimeout              = errors.New("handshake timeout")
	ErrInvalidSignature              = errors.New("invalid handshake signature")
)

// AuthenticatedPQXDHClient extends PQXDH client with certificate authentication
type AuthenticatedPQXDHClient struct {
	pqxdhClient *pqxdh.PQXDHClient
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
	verifier    *certs.ClientCertificateVerifier
	id          uuid.NullUUID // Optional client ID for identification
}

// AuthenticatedPQXDHServer extends PQXDH server with certificate authentication
type AuthenticatedPQXDHServer struct {
	pqxdhServer *pqxdh.PQXDHServer
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
	verifier    *certs.ClientCertificateVerifier // Unified approach for certificate verification
}

// NewAuthenticatedPQXDHClient creates a new authenticated PQXDH client
// privKey should be the private key corresponding to the server's certificate
func NewAuthenticatedPQXDHClient(cert *x509.Certificate, privKey ed25519.PrivateKey, verifier *certs.ClientCertificateVerifier, id uuid.NullUUID) *AuthenticatedPQXDHClient {
	return &AuthenticatedPQXDHClient{
		pqxdhClient: pqxdh.NewPQXDHClient(),
		certificate: cert,
		privateKey:  privKey,
		verifier:    verifier,
		id:          id,
	}
}

// NewAuthenticatedPQXDHServer creates a new authenticated PQXDH server
// privKey should be the private key corresponding to the server's certificate
func NewAuthenticatedPQXDHServer(cert *x509.Certificate, privKey ed25519.PrivateKey, verifier *certs.ClientCertificateVerifier) (*AuthenticatedPQXDHServer, error) {
	return &AuthenticatedPQXDHServer{
		pqxdhServer: pqxdh.NewPQXDHServer(),
		certificate: cert,
		privateKey:  privKey,
		verifier:    verifier,
	}, nil
}

// CreateClientHello creates an authenticated client hello message
func (ac *AuthenticatedPQXDHClient) CreateClientHello() (*AuthenticatedHandshakeHello, error) {
	// Get PQXDH public keys
	pqPubKey := ac.pqxdhClient.GetPQPublicKey()
	ecPubKey := ac.pqxdhClient.GetECPublicKey()

	// Serialize public keys
	pqPubKeyBytes := pqPubKey.Bytes()
	ecPubKeyBytes := ecPubKey.Bytes()

	// Create handshake message
	msg := &AuthenticatedHandshakeHello{
		PQPublicKey: pqPubKeyBytes,
		ECPublicKey: ecPubKeyBytes,
		Certificate: ac.certificate.Raw,
		Timestamp:   time.Now(),
		ID:          ac.id,
	}

	// Sign the message using the message's Sign method
	msg.Sign(ac.privateKey)

	return msg, nil
}

// ProcessClientHello processes an authenticated client hello and returns server response
func (as *AuthenticatedPQXDHServer) ProcessClientHello(clientHello *AuthenticatedHandshakeHello) (response *AuthenticatedHandshakeResponse, key []byte, err error) {
	// Validate client certificate using the verifier
	_, err = as.verifier.VerifyPeerCertificate(clientHello.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("client certificate verification failed: %w", err)
	}

	err = clientHello.Verify()
	if err != nil {
		return nil, nil, err
	}

	// Parse client PQXDH public keys
	clientPQPubKey, err := pqxdh.ParsePQPublicKey(clientHello.PQPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse client PQ public key: %w", err)
	}

	clientECPubKey, err := pqxdh.ParseECPublicKey(clientHello.ECPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse client EC public key: %w", err)
	}

	// Perform PQXDH server key exchange
	sharedKey, ciphertext, err := pqxdh.ServerKeyExchange(clientPQPubKey, clientECPubKey, *as.pqxdhServer)
	if err != nil {
		return nil, nil, fmt.Errorf("PQXDH server key exchange failed: %w", err)
	}

	// Create server response
	serverECPubKey := as.pqxdhServer.GetECPublicKey()
	response = &AuthenticatedHandshakeResponse{
		ECPublicKey: serverECPubKey.Bytes(),
		Certificate: as.certificate.Raw,
		Ciphertext:  ciphertext,
		Timestamp:   time.Now(),
	}

	// Sign server response using the message's Sign method
	response.Sign(as.privateKey)

	return response, sharedKey, nil
}

// ProcessServerResponse processes the authenticated server response and derives shared key
func (ac *AuthenticatedPQXDHClient) ProcessServerResponse(serverResponse *AuthenticatedHandshakeResponse) (key []byte, err error) {
	// Validate server certificate
	_, err = ac.verifier.VerifyPeerCertificate(serverResponse.Certificate)
	if err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	err = serverResponse.Verify()
	if err != nil {
		return nil, err
	}

	// Parse server EC public key
	serverECPubKey, err := pqxdh.ParseECPublicKey(serverResponse.ECPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server EC public key: %w", err)
	}

	// Perform PQXDH client key exchange
	sharedKey, err := pqxdh.ClientKeyExchange(serverECPubKey, serverResponse.Ciphertext, *ac.pqxdhClient)
	if err != nil {
		return nil, fmt.Errorf("PQXDH client key exchange failed: %w", err)
	}

	return sharedKey, nil
}
