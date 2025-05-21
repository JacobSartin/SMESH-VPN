package pqxdh

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
)

// PQXDH is a struct that implements the PQXDH key exchange protocol.
type PQXDHClient struct {
	// each peer has 2 key pairs
	// one ecdh and one pq kem
	pqPrivKey *mlkem.DecapsulationKey768
	ecPrivKey *ecdh.PrivateKey
}

// NewPQXDH creates a new PQXDH instance with the corresponding key pairs.
func NewPQXDHClient() *PQXDHClient {
	ecPrivKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	pqPrivKey, err := mlkem.GenerateKey768()
	if err != nil {
		panic(err)
	}

	return &PQXDHClient{
		pqPrivKey: pqPrivKey,
		ecPrivKey: ecPrivKey,
	}
}

// recieves the ciphertext and classical public key, generates a shared secret
func ClientKeyExchange(serverECPubKey *ecdh.PublicKey, pqCiphertext []byte, self PQXDHClient) (key []byte, err error) {
	// generates ec shared secret
	ecSharedSecret, err := self.ecPrivKey.ECDH(serverECPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// decapsulate the pq secret
	pqSharedSecret, err := self.pqPrivKey.Decapsulate(pqCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}

	key, err = KeyGen(ecSharedSecret, pqSharedSecret)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	return key, nil
}

// GetPQPublicKey returns the PQ public key of the client.
func (pqxdh *PQXDHClient) GetPQPublicKey() *mlkem.EncapsulationKey768 {
	return pqxdh.pqPrivKey.EncapsulationKey()
}

// GetECPublicKey returns the EC public key of the client.
func (pqxdh *PQXDHClient) GetECPublicKey() *ecdh.PublicKey {
	return pqxdh.ecPrivKey.PublicKey()
}
