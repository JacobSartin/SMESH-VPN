package auth

import (
	"crypto/mldsa"
	"fmt"
	"slices"
	"time"
)

type AuthenticatedHandshakeResponse struct {
	ECPublicKey []byte `json:"ec_public_key"` // X25519 public key

	// Certificate for identity verification
	Certificate []byte `json:"certificate"` // X.509 certificate in DER format

	// Signature over the handshake data using the certificate's private key
	Signature []byte `json:"signature"`

	// Timestamp to prevent replay attacks
	Timestamp time.Time `json:"timestamp"`

	// Ciphertext, encapsulated secret using ML-KEM
	Ciphertext []byte `json:"ciphertext"` // ML-KEM encapsulated secret
}

// Sign signs the handshake response message with the provided private key.
func (msg *AuthenticatedHandshakeResponse) signatureData() ([]byte, error) {
	timestampBytes, err := msg.Timestamp.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal timestamp: %w", err)
	}
	return slices.Concat(msg.ECPublicKey, msg.Certificate, msg.Ciphertext, timestampBytes), nil
}

func (msg *AuthenticatedHandshakeResponse) Sign(privateKey *mldsa.PrivateKey) error {
	data, err := msg.signatureData()
	if err != nil {
		return err
	}
	msg.Signature, err = signHandshake(privateKey, data)
	return err
}

// Verify verifies the signature of the handshake response message
func (msg *AuthenticatedHandshakeResponse) Verify() error {
	if !validHandshakeTime(msg.Timestamp) {
		return ErrHandshakeTimeout
	}
	data, err := msg.signatureData()
	if err != nil {
		return err
	}
	return verifyHandshake(msg.Certificate, data, msg.Signature)
}
