package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	// KeySize256 is the size of an AES-256 key in bytes
	KeySize256 = 32
	// NonceSize is the size of the GCM nonce
	NonceSize = 12
)

// Errors related to AES encryption and decryption
var (
	ErrInvalidKeySize    = errors.New("invalid key size, must be 32 bytes (256 bits)")
	ErrEncryptionFailed  = errors.New("encryption failed")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// AES256 represents a struct holding a 256-bit AES key for GCM mode operations
type AES256 struct {
	key []byte
	gcm cipher.AEAD
}

// NewAES256 creates a new AES-256 instance with the provided key
// The key must be exactly 32 bytes (256 bits)
func NewAES256(key []byte) (*AES256, error) {
	if len(key) != KeySize256 {
		return nil, ErrInvalidKeySize
	}

	// Create a new block cipher using the 256-bit key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create a new GCM (Galois Counter Mode) instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// TODO: remove key? already stored in the cipher
	// Create a copy of the key to prevent modification from outside
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &AES256{
		key: keyCopy,
		gcm: gcm,
	}, nil
}

// Encrypt encrypts the plaintext using AES-256-GCM
// It returns the ciphertext with the nonce prepended
func (a *AES256) Encrypt(plaintext []byte) ([]byte, error) {
	// Create a nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: failed to generate nonce", ErrEncryptionFailed)
	}

	// Encrypt and authenticate the plaintext
	ciphertext := a.gcm.Seal(nil, nonce, plaintext, nil)

	// Prepend the nonce to the ciphertext
	result := make([]byte, NonceSize+len(ciphertext))
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:], ciphertext)

	return result, nil
}

// Decrypt decrypts the ciphertext using AES-256-GCM
// The nonce should be prepended to the ciphertext
func (a *AES256) Decrypt(ciphertext []byte) ([]byte, error) {
	// Check if ciphertext is long enough to contain a nonce
	if len(ciphertext) < NonceSize {
		return nil, ErrInvalidCiphertext
	}

	// Extract the nonce from the ciphertext
	nonce := ciphertext[:NonceSize]
	encryptedData := ciphertext[NonceSize:]

	// Decrypt the ciphertext
	plaintext, err := a.gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// Call this method when you're done using the AES256 instance
// to ensure the key is zeroed out and not left in memory.
func (a *AES256) Close() {
	// Overwrite the key with zeros
	for i := range a.key {
		a.key[i] = 0
	}
}

// WithAES256 creates a new AES256 instance and automatically cleans up the key
// when the provided function completes, even if it panics.
// This is the recommended way to use AES256 for maximum safety.
//
// Example usage:
//
//	err := WithAES256(key, func(cipher *AES256) error {
//	    ciphertext, err := cipher.Encrypt(plaintext)
//	    if err != nil {
//	        return err
//	    }
//	    // Process ciphertext...
//	    return nil
//	})
func WithAES256(key []byte, fn func(*AES256) error) error {
	cipher, err := NewAES256(key)
	if err != nil {
		return err
	}

	// This ensures the key is wiped even if fn panics
	defer cipher.Close()

	// Execute the provided function with the cipher
	return fn(cipher)
}
