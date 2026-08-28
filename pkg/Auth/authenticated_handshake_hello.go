package auth

import (
	"crypto/mldsa"
	"fmt"
	"slices"
	"time"
	"uuid"
)

// AuthenticatedHandshakeMessage represents a PQXDH handshake message with certificate authentication
type AuthenticatedHandshakeHello struct {
	// PQXDH public keys
	PQPublicKey []byte `json:"pq_public_key"` // ML-KEM 768 public key
	ECPublicKey []byte `json:"ec_public_key"` // X25519 public key

	// Certificate for identity verification
	Certificate []byte `json:"certificate"` // X.509 certificate in DER format

	// Signature over the handshake data using the certificate's private key
	Signature []byte `json:"signature"`

	// Timestamp to prevent replay attacks
	Timestamp time.Time `json:"timestamp"`

	// client ID
	ID uuid.UUID `json:"id"`
}

// Sign signs the handshake hello message with the provided private key.
func (msg *AuthenticatedHandshakeHello) signatureData() ([]byte, error) {
	timestampBytes, err := msg.Timestamp.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal timestamp: %w", err)
	}
	parts := [][]byte{msg.PQPublicKey, msg.ECPublicKey, msg.Certificate, timestampBytes}
	if msg.ID != uuid.Nil() {
		parts = append(parts, msg.ID[:])
	}
	return slices.Concat(parts...), nil
}

func (msg *AuthenticatedHandshakeHello) Sign(privateKey *mldsa.PrivateKey) error {
	data, err := msg.signatureData()
	if err != nil {
		return err
	}
	msg.Signature, err = signHandshake(privateKey, data)
	return err
}

// Verify verifies the signature of the handshake hello message
func (msg *AuthenticatedHandshakeHello) Verify() error {
	if !validHandshakeTime(msg.Timestamp) {
		return ErrHandshakeTimeout
	}
	data, err := msg.signatureData()
	if err != nil {
		return err
	}
	return verifyHandshake(msg.Certificate, data, msg.Signature)
}
