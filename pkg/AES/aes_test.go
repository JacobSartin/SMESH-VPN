package aes

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// TestNewAES256 tests creation of a new AES256 instance
func TestNewAES256(t *testing.T) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// Create a new AES instance
	aesInstance, err := NewAES256(key)
	if err != nil {
		t.Fatalf("Failed to create AES instance: %v", err)
	}

	// Ensure the key was correctly copied
	if !bytes.Equal(aesInstance.key, key) {
		t.Errorf("Key was not correctly stored in the AES instance")
	}

	// Test with an invalid key size
	invalidKey := make([]byte, KeySize256-1) // 31 bytes instead of 32
	_, err = NewAES256(invalidKey)
	if err != ErrInvalidKeySize {
		t.Errorf("Expected invalid key size error, got: %v", err)
	}
}

// TestEncryptDecrypt tests the encryption and decryption functionality
func TestEncryptDecrypt(t *testing.T) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// Create a new AES instance
	aesInstance, err := NewAES256(key)
	if err != nil {
		t.Fatalf("Failed to create AES instance: %v", err)
	}

	// Test cases with different plaintext sizes
	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "Empty plaintext",
			plaintext: []byte{},
		},
		{
			name:      "Small plaintext",
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "Medium plaintext",
			plaintext: bytes.Repeat([]byte("SMESH-VPN "), 100),
		},
		{
			name:      "Large plaintext",
			plaintext: bytes.Repeat([]byte("Large data block for testing AES encryption and decryption. "), 1000),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt the plaintext
			ciphertext, err := aesInstance.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Check that ciphertext is not equal to plaintext (unless plaintext is empty)
			if len(tc.plaintext) > 0 && bytes.Equal(ciphertext, tc.plaintext) {
				t.Errorf("Ciphertext should not equal plaintext")
			}

			// Ensure the ciphertext is longer than plaintext by at least the nonce size
			minLength := len(tc.plaintext) + NonceSize
			if len(ciphertext) < minLength {
				t.Errorf("Ciphertext too short, expected at least %d bytes, got %d", minLength, len(ciphertext))
			}

			// Decrypt the ciphertext
			decrypted, err := aesInstance.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify the decrypted data matches the original plaintext
			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("Decrypted data does not match original plaintext")
			}
		})
	}
}

// TestDecryptInvalidData tests decryption with invalid data
func TestDecryptInvalidData(t *testing.T) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// Create a new AES instance
	aesInstance, err := NewAES256(key)
	if err != nil {
		t.Fatalf("Failed to create AES instance: %v", err)
	}

	// Test cases with invalid ciphertext
	testCases := []struct {
		name       string
		ciphertext []byte
		expectErr  error
	}{
		{
			name:       "Empty ciphertext",
			ciphertext: []byte{},
			expectErr:  ErrInvalidCiphertext,
		},
		{
			name:       "Ciphertext too short",
			ciphertext: make([]byte, NonceSize-1),
			expectErr:  ErrInvalidCiphertext,
		},
		{
			name:       "Invalid ciphertext",
			ciphertext: bytes.Repeat([]byte{0x42}, NonceSize+16), // Random data
			expectErr:  ErrDecryptionFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := aesInstance.Decrypt(tc.ciphertext)
			if err == nil {
				t.Fatalf("Expected error but got nil")
			}
		})
	}
}

// TestClose tests the secure wiping of the key
func TestClose(t *testing.T) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	// Create a new AES instance
	aesInstance, err := NewAES256(key)
	if err != nil {
		t.Fatalf("Failed to create AES instance: %v", err)
	}

	// Make sure the key is not all zeros
	allZeros := true
	for _, b := range aesInstance.key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Errorf("Key should not be all zeros initially")
	}

	// Zero out the key
	aesInstance.Close()

	// Verify the key is now all zeros
	for i, b := range aesInstance.key {
		if b != 0 {
			t.Errorf("Key byte at position %d is not zero after Close call", i)
		}
	}
}

// BenchmarkEncrypt benchmarks the encryption performance
func BenchmarkEncrypt(b *testing.B) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		b.Fatalf("Failed to generate random key: %v", err)
	}

	// Create a new AES instance
	aesInstance, err := NewAES256(key)
	if err != nil {
		b.Fatalf("Failed to create AES instance: %v", err)
	}

	// Generate plaintext (1KB)
	plaintext := make([]byte, 1024)
	_, err = io.ReadFull(rand.Reader, plaintext)
	if err != nil {
		b.Fatalf("Failed to generate random plaintext: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aesInstance.Encrypt(plaintext)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkDecrypt benchmarks the decryption performance
func BenchmarkDecrypt(b *testing.B) {
	// Generate a random key
	key := make([]byte, KeySize256)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		b.Fatalf("Failed to generate random key: %v", err)
	}

	// Create a new AES instance
	aesInstance, err := NewAES256(key)
	if err != nil {
		b.Fatalf("Failed to create AES instance: %v", err)
	}

	// Generate plaintext (1KB) and encrypt it
	plaintext := make([]byte, 1024)
	_, err = io.ReadFull(rand.Reader, plaintext)
	if err != nil {
		b.Fatalf("Failed to generate random plaintext: %v", err)
	}
	ciphertext, err := aesInstance.Encrypt(plaintext)
	if err != nil {
		b.Fatalf("Failed to encrypt plaintext: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aesInstance.Decrypt(ciphertext)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
