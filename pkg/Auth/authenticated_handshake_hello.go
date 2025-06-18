package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AuthenticatedHandshakeMessage represents a PQXDH handshake message with certificate authentication
type AuthenticatedHandshakeHello struct {
	// PQXDH public keys
	PQPublicKey []byte // ML-KEM 768 public key
	ECPublicKey []byte // X25519 public key

	// Certificate for identity verification
	Certificate []byte // X.509 certificate in DER format

	// Signature over the handshake data using the certificate's private key
	Signature []byte

	// Timestamp to prevent replay attacks
	Timestamp time.Time

	// client ID
	ID uuid.NullUUID
}

// jsonAuthenticatedHandshakeHello is an intermediate struct for JSON marshaling
type jsonAuthenticatedHandshakeHello struct {
	PQPublicKey []byte        `json:"pq_public_key"`
	ECPublicKey []byte        `json:"ec_public_key"`
	Certificate []byte        `json:"certificate"`
	Signature   []byte        `json:"signature"`
	Timestamp   time.Time     `json:"timestamp"`
	ID          uuid.NullUUID `json:"id"`
}

// MarshalJSON implements custom JSON marshaling for AuthenticatedHandshakeHello
func (msg *AuthenticatedHandshakeHello) MarshalJSON() ([]byte, error) {
	intermediate := jsonAuthenticatedHandshakeHello{
		PQPublicKey: msg.PQPublicKey,
		ECPublicKey: msg.ECPublicKey,
		Certificate: msg.Certificate,
		Signature:   msg.Signature,
		Timestamp:   msg.Timestamp,
		ID:          msg.ID,
	}
	return json.Marshal(intermediate)
}

// UnmarshalJSON implements custom JSON unmarshaling for AuthenticatedHandshakeHello
func (msg *AuthenticatedHandshakeHello) UnmarshalJSON(data []byte) error {
	var intermediate jsonAuthenticatedHandshakeHello
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return err
	}

	msg.PQPublicKey = intermediate.PQPublicKey
	msg.ECPublicKey = intermediate.ECPublicKey
	msg.Certificate = intermediate.Certificate
	msg.Signature = intermediate.Signature
	msg.Timestamp = intermediate.Timestamp
	msg.ID = intermediate.ID

	return nil
}

// signs the handshake hello message with the provided private key
func (msg *AuthenticatedHandshakeHello) Sign(privateKey ed25519.PrivateKey) {
	signatureData := append(msg.PQPublicKey, msg.ECPublicKey...)
	signatureData = append(signatureData, msg.Certificate...)
	timestampBytes, _ := msg.Timestamp.MarshalBinary()
	signatureData = append(signatureData, timestampBytes...)

	// Include ID in signature if present
	if msg.ID.Valid {
		idBytes, _ := msg.ID.UUID.MarshalBinary()
		signatureData = append(signatureData, idBytes...)
	}

	msg.Signature = ed25519.Sign(privateKey, signatureData)
}

// Verify verifies the signature of the handshake hello message
func (msg *AuthenticatedHandshakeHello) Verify() error {
	// Parse the certificate
	cert, err := x509.ParseCertificate(msg.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify the signature using the public key from the certificate
	signatureData := append(msg.PQPublicKey, msg.ECPublicKey...)
	signatureData = append(signatureData, msg.Certificate...)
	timestampBytes, _ := msg.Timestamp.MarshalBinary()
	signatureData = append(signatureData, timestampBytes...)

	// Include ID in signature if present
	if msg.ID.Valid {
		idBytes, _ := msg.ID.UUID.MarshalBinary()
		signatureData = append(signatureData, idBytes...)
	}

	// ensure time is not too old to prevent replay attacks
	if time.Since(msg.Timestamp) > 5*time.Minute {
		return ErrHandshakeTimeout
	}

	if !ed25519.Verify(cert.PublicKey.(ed25519.PublicKey), signatureData, msg.Signature) {
		return ErrInvalidSignature
	}

	return nil
}
