package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"
)

type AuthenticatedHandshakeResponse struct {
	ECPublicKey []byte // X25519 public key

	// Certificate for identity verification
	Certificate []byte // X.509 certificate in DER format

	// Signature over the handshake data using the certificate's private key
	Signature []byte

	// Timestamp to prevent replay attacks
	Timestamp time.Time

	// Ciphertext, encapsulated secret using ML-KEM
	Ciphertext []byte // ML-KEM encapsulated secret
}

// jsonAuthenticatedHandshakeResponse is an intermediate struct for JSON marshaling
type jsonAuthenticatedHandshakeResponse struct {
	ECPublicKey []byte    `json:"ec_public_key"`
	Certificate []byte    `json:"certificate"`
	Signature   []byte    `json:"signature"`
	Timestamp   time.Time `json:"timestamp"`
	Ciphertext  []byte    `json:"ciphertext"`
}

// MarshalJSON implements custom JSON marshaling for AuthenticatedHandshakeResponse
func (msg *AuthenticatedHandshakeResponse) MarshalJSON() ([]byte, error) {
	intermediate := jsonAuthenticatedHandshakeResponse{
		ECPublicKey: msg.ECPublicKey,
		Certificate: msg.Certificate,
		Signature:   msg.Signature,
		Timestamp:   msg.Timestamp,
		Ciphertext:  msg.Ciphertext,
	}
	return json.Marshal(intermediate)
}

// UnmarshalJSON implements custom JSON unmarshaling for AuthenticatedHandshakeResponse
func (msg *AuthenticatedHandshakeResponse) UnmarshalJSON(data []byte) error {
	var intermediate jsonAuthenticatedHandshakeResponse
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return err
	}

	msg.ECPublicKey = intermediate.ECPublicKey
	msg.Certificate = intermediate.Certificate
	msg.Signature = intermediate.Signature
	msg.Timestamp = intermediate.Timestamp
	msg.Ciphertext = intermediate.Ciphertext

	return nil
}

// signs the handshake response message with the provided private key
func (msg *AuthenticatedHandshakeResponse) Sign(privateKey ed25519.PrivateKey) {
	signatureData := append(msg.ECPublicKey, msg.Certificate...)
	signatureData = append(signatureData, msg.Ciphertext...)
	timestampBytes, _ := msg.Timestamp.MarshalBinary()
	signatureData = append(signatureData, timestampBytes...)

	msg.Signature = ed25519.Sign(privateKey, signatureData)
}

// Verify verifies the signature of the handshake response message
func (msg *AuthenticatedHandshakeResponse) Verify() error {
	// Parse the certificate
	cert, err := x509.ParseCertificate(msg.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify the signature using the public key from the certificate
	signatureData := append(msg.ECPublicKey, msg.Certificate...)
	signatureData = append(signatureData, msg.Ciphertext...)
	timestampBytes, _ := msg.Timestamp.MarshalBinary()
	signatureData = append(signatureData, timestampBytes...)

	// ensure time is not too old to prevent replay attacks
	if time.Since(msg.Timestamp) > 5*time.Minute {
		return ErrHandshakeTimeout
	}

	if !ed25519.Verify(cert.PublicKey.(ed25519.PublicKey), signatureData, msg.Signature) {
		return ErrInvalidSignature
	}

	return nil
}
