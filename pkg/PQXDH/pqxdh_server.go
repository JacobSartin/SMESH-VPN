package pqxdh

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
)

// PQXDH is a struct that implements the PQXDH key exchange protocol.
type PQXDHServer struct {
	ecPrivKey *ecdh.PrivateKey
}

// NewPQXDHServer creates a new PQXDH instance with the corresponding key pairs.
func NewPQXDHServer() *PQXDHServer {
	ecPrivKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return &PQXDHServer{
		ecPrivKey: ecPrivKey,
	}
}

// recieves the public keys from the other peer, generates a shared secret
// then encapsulates the pq secret to send to the client
func ServerKeyExchange(clientPQPubKey *mlkem.EncapsulationKey768, clientECPubKey *ecdh.PublicKey, self PQXDHServer) (key []byte, ciphertext []byte, err error) {
	ecSharedSecret, err := self.ecPrivKey.ECDH(clientECPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH failed: %w", err)
	}

	pqSharedSecret, ciphertext := clientPQPubKey.Encapsulate()

	// combine the secrets
	combinedSecret := make([]byte, len(pqSharedSecret)+len(ecSharedSecret[:]))
	copy(combinedSecret, pqSharedSecret)
	copy(combinedSecret[len(pqSharedSecret):], ecSharedSecret[:])

	key, err = KeyGen(ecSharedSecret, pqSharedSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("key generation failed: %w", err)
	}

	return key, ciphertext, nil
}

// GetECPublicKey returns the EC public key of the server.
func (pqxdh *PQXDHServer) GetECPublicKey() *ecdh.PublicKey {
	return pqxdh.ecPrivKey.PublicKey()
}
