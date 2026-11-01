// Package auth provides certificate-authenticated PQXDH key exchange
// This integrates the existing Certificate Authority system with PQXDH handshakes
package auth

import (
	"crypto/mldsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
	"uuid"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	pqxdh "github.com/JacobSartin/SMESH-VPN/pkg/PQXDH"
)

// Errors for authenticated key exchange
var (
	ErrInvalidCertificate  = errors.New("invalid certificate")
	ErrHandshakeTimeout    = errors.New("handshake timeout")
	ErrInvalidSignature    = errors.New("invalid handshake signature")
	ErrHandshakeOutOfOrder = errors.New("server response processed before client hello was created")
)

// AuthenticatedPQXDHClient extends PQXDH client with certificate authentication
type AuthenticatedPQXDHClient struct {
	pqxdhClient *pqxdh.PQXDHClient
	certificate *x509.Certificate
	privateKey  *mldsa.PrivateKey
	verifier    *certs.ClientCertificateVerifier
	helloHash   []byte
}

// AuthenticatedPQXDHServer extends PQXDH server with certificate authentication
type AuthenticatedPQXDHServer struct {
	pqxdhServer *pqxdh.PQXDHServer
	certificate *x509.Certificate
	privateKey  *mldsa.PrivateKey
	verifier    *certs.ClientCertificateVerifier // Unified approach for certificate verification
}

// NewAuthenticatedPQXDHClient creates a new authenticated PQXDH client.
// cert must be a client certificate carrying a client ID.
func NewAuthenticatedPQXDHClient(cert *x509.Certificate, privKey *mldsa.PrivateKey, verifier *certs.ClientCertificateVerifier) (*AuthenticatedPQXDHClient, error) {
	if _, err := certs.ClientIDFromCertificate(cert); err != nil {
		return nil, err
	}
	pqxdhClient, err := pqxdh.NewPQXDHClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create PQXDH client: %w", err)
	}

	return &AuthenticatedPQXDHClient{
		pqxdhClient: pqxdhClient,
		certificate: cert,
		privateKey:  privKey,
		verifier:    verifier,
	}, nil
}

// NewAuthenticatedPQXDHServer creates a new authenticated PQXDH server
// privKey should be the private key corresponding to the server's certificate
func NewAuthenticatedPQXDHServer(cert *x509.Certificate, privKey *mldsa.PrivateKey, verifier *certs.ClientCertificateVerifier) (*AuthenticatedPQXDHServer, error) {
	pqxdhServer, err := pqxdh.NewPQXDHServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create PQXDH server: %w", err)
	}

	return &AuthenticatedPQXDHServer{
		pqxdhServer: pqxdhServer,
		certificate: cert,
		privateKey:  privKey,
		verifier:    verifier,
	}, nil
}

// CreateClientHello creates an authenticated client hello message
func (ac *AuthenticatedPQXDHClient) CreateClientHello() (*AuthenticatedHandshakeHello, error) {
	msg := &AuthenticatedHandshakeHello{
		PQPublicKey: ac.pqxdhClient.GetPQPublicKey().Bytes(),
		ECPublicKey: ac.pqxdhClient.GetECPublicKey().Bytes(),
		Certificate: ac.certificate.Raw,
		Timestamp:   time.Now(),
	}

	if err := msg.Sign(ac.privateKey); err != nil {
		return nil, fmt.Errorf("failed to sign client hello: %w", err)
	}

	ac.helloHash = msg.transcriptHash()

	return msg, nil
}

// ProcessClientHello processes an authenticated client hello and returns the
// server response, the shared key, and the initiator's verified client ID.
func (as *AuthenticatedPQXDHServer) ProcessClientHello(clientHello *AuthenticatedHandshakeHello) (response *AuthenticatedHandshakeResponse, key []byte, peerID uuid.UUID, err error) {
	peerID, err = verifiedPeerID(as.verifier, clientHello.Certificate)
	if err != nil {
		return nil, nil, uuid.Nil(), fmt.Errorf("client certificate verification failed: %w", err)
	}

	if err := clientHello.Verify(); err != nil {
		return nil, nil, uuid.Nil(), err
	}

	clientPQPubKey, err := pqxdh.ParsePQPublicKey(clientHello.PQPublicKey)
	if err != nil {
		return nil, nil, uuid.Nil(), fmt.Errorf("failed to parse client PQ public key: %w", err)
	}

	clientECPubKey, err := pqxdh.ParseECPublicKey(clientHello.ECPublicKey)
	if err != nil {
		return nil, nil, uuid.Nil(), fmt.Errorf("failed to parse client EC public key: %w", err)
	}

	sharedKey, ciphertext, err := pqxdh.ServerKeyExchange(clientPQPubKey, clientECPubKey, *as.pqxdhServer)
	if err != nil {
		return nil, nil, uuid.Nil(), fmt.Errorf("PQXDH server key exchange failed: %w", err)
	}

	response = &AuthenticatedHandshakeResponse{
		ECPublicKey: as.pqxdhServer.GetECPublicKey().Bytes(),
		Certificate: as.certificate.Raw,
		Ciphertext:  ciphertext,
		Timestamp:   time.Now(),
	}

	if err := response.Sign(as.privateKey, clientHello.transcriptHash()); err != nil {
		return nil, nil, uuid.Nil(), fmt.Errorf("failed to sign server response: %w", err)
	}

	return response, sharedKey, peerID, nil
}

// ProcessServerResponse processes the authenticated server response and derives
// the shared key. It returns the responder's verified client ID.
func (ac *AuthenticatedPQXDHClient) ProcessServerResponse(serverResponse *AuthenticatedHandshakeResponse) (key []byte, peerID uuid.UUID, err error) {
	if ac.helloHash == nil {
		return nil, uuid.Nil(), ErrHandshakeOutOfOrder
	}

	peerID, err = verifiedPeerID(ac.verifier, serverResponse.Certificate)
	if err != nil {
		return nil, uuid.Nil(), fmt.Errorf("certificate validation failed: %w", err)
	}

	if err := serverResponse.Verify(ac.helloHash); err != nil {
		return nil, uuid.Nil(), err
	}

	serverECPubKey, err := pqxdh.ParseECPublicKey(serverResponse.ECPublicKey)
	if err != nil {
		return nil, uuid.Nil(), fmt.Errorf("failed to parse server EC public key: %w", err)
	}

	sharedKey, err := pqxdh.ClientKeyExchange(serverECPubKey, serverResponse.Ciphertext, *ac.pqxdhClient)
	if err != nil {
		return nil, uuid.Nil(), fmt.Errorf("PQXDH client key exchange failed: %w", err)
	}

	return sharedKey, peerID, nil
}

// verifiedPeerID checks certDER against the trusted CA and returns the client ID it carries.
func verifiedPeerID(verifier *certs.ClientCertificateVerifier, certDER []byte) (uuid.UUID, error) {
	cert, err := verifier.VerifyPeerCertificate(certDER)
	if err != nil {
		return uuid.Nil(), err
	}
	id, err := certs.ClientIDFromCertificate(cert)
	if err != nil {
		return uuid.Nil(), err
	}
	return id, nil
}
