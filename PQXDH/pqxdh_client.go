package pqxdh

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// PQXDH is a struct that implements the PQXDH key exchange protocol.
type PQXDHClient struct {
	// each peer has 2 key pairs
	// one ecdh and one pq kem
	pqPubKey  *mlkem1024.PublicKey
	pqPrivKey *mlkem1024.PrivateKey
	ecPubKey  *x448.Key
	ecPrivKey *x448.Key
}

// NewPQXDH creates a new PQXDH instance with the corresponding key pairs.
func NewPQXDHClient() *PQXDHClient {
	var ecPubKey, ecPrivKey x448.Key

	// Generate a new PQXDH instance with a new key pair.
	pqPubKey, pqPrivKey, err := mlkem1024.GenerateKeyPair(nil)
	if err != nil {
		panic(err)
	}

	// Generate a new X448 key pair.
	_, _ = io.ReadFull(rand.Reader, ecPrivKey[:])
	x448.KeyGen(&ecPubKey, &ecPrivKey)

	return &PQXDHClient{
		pqPubKey:  pqPubKey,
		pqPrivKey: pqPrivKey,
		ecPubKey:  &ecPubKey,
		ecPrivKey: &ecPrivKey,
	}
}

// recieves the ciphertext and classical public key, generates a shared secret
func ClientKeyExchange(serverECPubKey *x448.Key, pqCiphertext []byte, self PQXDHClient) (key []byte, err error) {
	pqSharedSecret := make([]byte, mlkem1024.SharedKeySize)
	var ecSharedSecret x448.Key

	// generates ec shared secret
	x448.Shared(&ecSharedSecret, self.ecPrivKey, serverECPubKey)

	// decapsulate the pq secret
	self.pqPrivKey.DecapsulateTo(pqSharedSecret, pqCiphertext)

	key, err = KeyGen(ecSharedSecret, pqSharedSecret)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	return key, nil
}

// GetPQPublicKey returns the PQ public key of the client.
func (self *PQXDHClient) GetPQPublicKey() *mlkem1024.PublicKey {
	return self.pqPubKey
}

// GetECPublicKey returns the EC public key of the client.
func (self *PQXDHClient) GetECPublicKey() *x448.Key {
	return self.ecPubKey
}
