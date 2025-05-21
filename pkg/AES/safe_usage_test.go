package aes

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// TestDeferClose demonstrates using defer with Close() for cleanup
func TestDeferClose(t *testing.T) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// Save a copy to check zeroing later
	keyCopy := make([]byte, KeySize256)
	copy(keyCopy, key)

	var cipher *AES256

	// Function that uses the cipher and might panic
	func() {
		// Create cipher and ensure cleanup with defer
		cipher, err = NewAES256(key)
		if err != nil {
			t.Fatalf("Failed to create AES cipher: %v", err)
		}
		defer cipher.Close()

		// Use the cipher
		plaintext := []byte("This is a secret message")
		_, err = cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// No need to manually call Close() - defer handles it
	}()

	// Verify the key was zeroed
	for i, b := range cipher.key {
		if b != 0 {
			t.Errorf("Key byte at position %d was not zeroed", i)
		}
	}
}

// TestWithAES256 demonstrates the WithAES256 helper pattern
func TestWithAES256(t *testing.T) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// Message to encrypt
	message := []byte("This is a secret message")
	var encrypted []byte

	// First use case - simple encryption
	err = WithAES256(key, func(cipher *AES256) error {
		var encErr error
		encrypted, encErr = cipher.Encrypt(message)
		return encErr
	})
	if err != nil {
		t.Fatalf("WithAES256 encryption failed: %v", err)
	}

	// Second use case - decryption
	var decrypted []byte
	err = WithAES256(key, func(cipher *AES256) error {
		var decErr error
		decrypted, decErr = cipher.Decrypt(encrypted)
		return decErr
	})
	if err != nil {
		t.Fatalf("WithAES256 decryption failed: %v", err)
	}

	// Verify roundtrip worked
	if !bytes.Equal(message, decrypted) {
		t.Errorf("Decrypted message doesn't match original")
	}
}

// TestWithAES256Panic tests that the key is safely zeroed even if the function panics
func TestWithAES256Panic(t *testing.T) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	var cipher *AES256

	// Use recover to catch the panic
	var recovered interface{}
	func() {
		defer func() {
			recovered = recover()
		}()

		// This should panic but still zero the key
		_ = WithAES256(key, func(c *AES256) error {
			cipher = c // Save reference for inspection
			panic("intentional panic for testing")
		})
	}()

	// Verify we caught the panic
	if recovered == nil {
		t.Fatalf("Expected panic was not triggered")
	}

	// Verify the key was still zeroed despite the panic
	for i, b := range cipher.key {
		if b != 0 {
			t.Errorf("Key byte at position %d was not zeroed after panic", i)
		}
	}
}

// TestChainedOperations shows how to perform multiple operations with the same key
func TestChainedOperations(t *testing.T) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	message1 := []byte("First message")
	message2 := []byte("Second message")
	var encrypted1, encrypted2 []byte

	// Encrypt multiple messages using the same key
	err = WithAES256(key, func(cipher *AES256) error {
		var err error

		// First encryption
		encrypted1, err = cipher.Encrypt(message1)
		if err != nil {
			return err
		}

		// Second encryption
		encrypted2, err = cipher.Encrypt(message2)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt both messages
	err = WithAES256(key, func(cipher *AES256) error {
		// First decryption
		decrypted1, err := cipher.Decrypt(encrypted1)
		if err != nil {
			return err
		}
		if !bytes.Equal(decrypted1, message1) {
			return errors.New("first decryption failed")
		}

		// Second decryption
		decrypted2, err := cipher.Decrypt(encrypted2)
		if err != nil {
			return err
		}
		if !bytes.Equal(decrypted2, message2) {
			return errors.New("second decryption failed")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
}
