package auth

import (
	"crypto/mldsa"
	"crypto/sha256"
	"slices"
	"time"
)

// AuthenticatedHandshakeHello is the initiator's PQXDH hello, signed with the
// key bound to its certificate.
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
}

func (msg *AuthenticatedHandshakeHello) signatureData() []byte {
	return slices.Concat(msg.PQPublicKey, msg.ECPublicKey, msg.Certificate, timestampBytes(msg.Timestamp))
}

// transcriptHash identifies this hello so the response signature can be bound to it.
func (msg *AuthenticatedHandshakeHello) transcriptHash() []byte {
	hash := sha256.Sum256(msg.signatureData())
	return hash[:]
}

// Sign signs the handshake hello message with the provided private key.
func (msg *AuthenticatedHandshakeHello) Sign(privateKey *mldsa.PrivateKey) error {
	signature, err := signHandshake(privateKey, msg.signatureData())
	if err != nil {
		return err
	}
	msg.Signature = signature
	return nil
}

// Verify verifies the signature of the handshake hello message
func (msg *AuthenticatedHandshakeHello) Verify() error {
	if !validHandshakeTime(msg.Timestamp) {
		return ErrHandshakeTimeout
	}
	return verifyHandshake(msg.Certificate, msg.signatureData(), msg.Signature)
}
