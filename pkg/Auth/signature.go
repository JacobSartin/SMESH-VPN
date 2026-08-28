package auth

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"time"
)

const maxHandshakeClockSkew = 5 * time.Minute

func signHandshake(key *mldsa.PrivateKey, data []byte) ([]byte, error) {
	return key.Sign(rand.Reader, data, crypto.Hash(0))
}

func verifyHandshake(certificate, data, signature []byte) error {
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return err
	}
	publicKey, ok := cert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return ErrInvalidCertificate
	}
	if err := mldsa.Verify(publicKey, data, signature, nil); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

func validHandshakeTime(timestamp time.Time) bool {
	delta := time.Since(timestamp)
	return delta >= -maxHandshakeClockSkew && delta <= maxHandshakeClockSkew
}
