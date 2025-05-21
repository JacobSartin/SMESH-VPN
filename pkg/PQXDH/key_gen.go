package pqxdh

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// generate a 256 bit key from the shared secrets
func KeyGen(ecSecret []byte, pqSecret []byte) (key []byte, err error) {
	// combine the secrets
	combinedSecret := make([]byte, len(pqSecret)+len(ecSecret[:]))
	copy(combinedSecret, pqSecret)
	copy(combinedSecret[len(pqSecret):], ecSecret[:])

	h := hkdf.New(sha256.New, combinedSecret, nil, []byte("SMESH-VPN-v1"))

	key = make([]byte, 32)
	// generate the key
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}

	return key, nil
}
