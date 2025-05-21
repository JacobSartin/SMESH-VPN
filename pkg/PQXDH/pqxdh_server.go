package pqxdh

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// PQXDH is a struct that implements the PQXDH key exchange protocol.
type PQXDHServer struct {
	ecPubKey  *x448.Key
	ecPrivKey *x448.Key
}

// NewPQXDHServer creates a new PQXDH instance with the corresponding key pairs.
func NewPQXDHServer() *PQXDHServer {
	var ecPubKey, ecPrivKey x448.Key

	// Generate a new X448 key pair.
	_, _ = io.ReadFull(rand.Reader, ecPrivKey[:])
	x448.KeyGen(&ecPubKey, &ecPrivKey)

	return &PQXDHServer{
		ecPubKey:  &ecPubKey,
		ecPrivKey: &ecPrivKey,
	}
}

// recieves the public keys from the other peer, generates a shared secret
// then encapsulates the pq secret to send to the client
func ServerKeyExchange(clientPQPubKey *mlkem1024.PublicKey, clientECPubKey *x448.Key, self PQXDHServer) (key []byte, ciphertext []byte, err error) {
	ciphertext = make([]byte, mlkem1024.CiphertextSize)
	pqSharedSecret := make([]byte, mlkem1024.SharedKeySize)
	var ecSharedSecret x448.Key

	// generates pq shared secret and encapsulates the pq secret
	clientPQPubKey.EncapsulateTo(ciphertext, pqSharedSecret, nil)

	// generates ec shared secret
	x448.Shared(&ecSharedSecret, self.ecPrivKey, clientECPubKey)

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
func (self *PQXDHServer) GetECPublicKey() *x448.Key {
	return self.ecPubKey
}
