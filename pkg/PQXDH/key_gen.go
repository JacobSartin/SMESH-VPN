package pqxdh

import (
	"crypto/hkdf"
	"crypto/sha3"
)

// generate a 256 bit key from the shared secrets
func KeyGen(ecSecret []byte, pqSecret []byte) (key []byte, err error) {
	// combine the secrets
	combinedSecret := make([]byte, len(pqSecret)+len(ecSecret[:]))
	copy(combinedSecret, pqSecret)
	copy(combinedSecret[len(pqSecret):], ecSecret[:])

	key, err = hkdf.Key(sha3.New256, combinedSecret, nil, "SMESH-VPN-v1", 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}
