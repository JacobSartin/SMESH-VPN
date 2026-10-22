package auth

import (
	"crypto/mldsa"
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

// signatureData covers the response fields and the hash of the hello being answered,
// so a response cannot be replayed against a different hello.
func (msg *AuthenticatedHandshakeResponse) signatureData(helloHash []byte) []byte {
	return slices.Concat(helloHash, msg.ECPublicKey, msg.Certificate, msg.Ciphertext, timestampBytes(msg.Timestamp))
}

// Sign signs the handshake response message, bound to the given hello hash.
func (msg *AuthenticatedHandshakeResponse) Sign(privateKey *mldsa.PrivateKey, helloHash []byte) error {
	signature, err := signHandshake(privateKey, msg.signatureData(helloHash))
	if err != nil {
		return err
	}
	msg.Signature = signature
	return nil
}

// Verify verifies the signature of the handshake response message against the hello hash.
func (msg *AuthenticatedHandshakeResponse) Verify(helloHash []byte) error {
	if !validHandshakeTime(msg.Timestamp) {
		return ErrHandshakeTimeout
	}
	return verifyHandshake(msg.Certificate, msg.signatureData(helloHash), msg.Signature)
}
