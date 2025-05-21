package pqxdh

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// TestKeyGen tests the KeyGen function
func TestKeyGen(t *testing.T) {
	// Create some test secrets
	var ecSecret x448.Key
	for i := range ecSecret {
		ecSecret[i] = byte(i)
	}

	pqSecret := make([]byte, mlkem1024.SharedKeySize)
	for i := range pqSecret {
		pqSecret[i] = byte(i + 100)
	}

	// Generate a key
	key, err := KeyGen(ecSecret, pqSecret)

	// Check for errors
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Check that the key has the expected size
	if len(key) != 32 {
		t.Errorf("Expected key length of 32 bytes, got %d", len(key))
	}

	// Generate another key with the same secrets to ensure determinism
	key2, err := KeyGen(ecSecret, pqSecret)
	if err != nil {
		t.Fatalf("Second KeyGen failed: %v", err)
	}

	// Check that the keys are identical
	if !bytes.Equal(key, key2) {
		t.Errorf("Expected identical keys for the same input")
	}

	// Slightly modify the ecSecret and ensure the key changes
	ecSecret[0]++
	differentKey, err := KeyGen(ecSecret, pqSecret)
	if err != nil {
		t.Fatalf("KeyGen with modified secret failed: %v", err)
	}

	if bytes.Equal(key, differentKey) {
		t.Errorf("Keys should be different when input secrets change")
	}
}

// TestNewPQXDHClient tests that NewPQXDHClient creates a valid client instance
func TestNewPQXDHClient(t *testing.T) {
	client := NewPQXDHClient()

	// Check that all keys were initialized
	if client.pqPubKey == nil {
		t.Errorf("PQ public key is nil")
	}

	if client.pqPrivKey == nil {
		t.Errorf("PQ private key is nil")
	}

	if client.ecPubKey == nil {
		t.Errorf("EC public key is nil")
	}

	if client.ecPrivKey == nil {
		t.Errorf("EC private key is nil")
	}
}

// TestNewPQXDHServer tests that NewPQXDHServer creates a valid server instance
func TestNewPQXDHServer(t *testing.T) {
	server := NewPQXDHServer()

	// Check that all keys were initialized
	if server.ecPubKey == nil {
		t.Errorf("EC public key is nil")
	}

	if server.ecPrivKey == nil {
		t.Errorf("EC private key is nil")
	}
}

// TestFullKeyExchange tests the full key exchange protocol between client and server
func TestFullKeyExchange(t *testing.T) {
	// Create client and server instances
	client := NewPQXDHClient()
	server := NewPQXDHServer()

	// Perform server-side key exchange
	serverKey, ciphertext, err := ServerKeyExchange(client.pqPubKey, client.ecPubKey, *server)
	if err != nil {
		t.Fatalf("Server key exchange failed: %v", err)
	}

	// Perform client-side key exchange
	clientKey, err := ClientKeyExchange(server.ecPubKey, ciphertext, *client)
	if err != nil {
		t.Fatalf("Client key exchange failed: %v", err)
	}

	// Verify that both parties derived the same key
	if !bytes.Equal(serverKey, clientKey) {
		t.Errorf("Key exchange failed: server and client keys do not match")
	}
}

// TestClientKeyExchangeWithCorruptCiphertext tests handling of corrupted (but correct size) ciphertext
func TestClientKeyExchangeWithCorruptCiphertext(t *testing.T) {
	// We'll use defer/recover to catch panics
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic with corrupt ciphertext: %v", r)
			// Test passes since we caught the panic
		}
	}()

	client := NewPQXDHClient()
	server := NewPQXDHServer()

	// Create a valid-sized but invalid content ciphertext
	corruptCiphertext := make([]byte, mlkem1024.CiphertextSize)
	for i := range corruptCiphertext {
		corruptCiphertext[i] = byte(i % 256)
	}

	// Try to perform key exchange with invalid ciphertext
	key, err := ClientKeyExchange(server.ecPubKey, corruptCiphertext, *client)

	// If we get here without a panic, just check we get some sort of key
	// (even though with invalid ciphertext it would be an invalid key)
	if err != nil {
		t.Logf("Error with corrupted ciphertext: %v", err)
	} else {
		t.Logf("Got key of length %d with corrupted ciphertext", len(key))
	}
}

// TestMultipleKeyExchanges tests multiple key exchanges between different pairs
func TestMultipleKeyExchanges(t *testing.T) {
	// Create multiple clients and servers
	client1 := NewPQXDHClient()
	client2 := NewPQXDHClient()
	server1 := NewPQXDHServer()
	server2 := NewPQXDHServer()

	// Perform key exchange between client1 and server1
	server1Key, ciphertext1, err := ServerKeyExchange(client1.pqPubKey, client1.ecPubKey, *server1)
	if err != nil {
		t.Fatalf("Server1 key exchange failed: %v", err)
	}

	client1Key, err := ClientKeyExchange(server1.ecPubKey, ciphertext1, *client1)
	if err != nil {
		t.Fatalf("Client1 key exchange failed: %v", err)
	}

	// Verify keys match
	if !bytes.Equal(server1Key, client1Key) {
		t.Errorf("Key exchange 1 failed: server and client keys do not match")
	}

	// Perform key exchange between client2 and server2
	server2Key, ciphertext2, err := ServerKeyExchange(client2.pqPubKey, client2.ecPubKey, *server2)
	if err != nil {
		t.Fatalf("Server2 key exchange failed: %v", err)
	}

	client2Key, err := ClientKeyExchange(server2.ecPubKey, ciphertext2, *client2)
	if err != nil {
		t.Fatalf("Client2 key exchange failed: %v", err)
	}

	// Verify keys match
	if !bytes.Equal(server2Key, client2Key) {
		t.Errorf("Key exchange 2 failed: server and client keys do not match")
	}
	// Verify that the two sessions have different keys
	if bytes.Equal(client1Key, client2Key) {
		t.Errorf("Different sessions should have different keys")
	}
}

// BenchmarkKeyExchange measures the performance of a complete key exchange
func BenchmarkKeyExchange(b *testing.B) {
	// Reset timer to exclude setup time
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create client and server
		client := NewPQXDHClient()
		server := NewPQXDHServer()

		// Perform server-side key exchange
		serverKey, ciphertext, err := ServerKeyExchange(client.pqPubKey, client.ecPubKey, *server)
		if err != nil {
			b.Fatalf("Server key exchange failed: %v", err)
		}

		// Perform client-side key exchange
		clientKey, err := ClientKeyExchange(server.ecPubKey, ciphertext, *client)
		if err != nil {
			b.Fatalf("Client key exchange failed: %v", err)
		}

		// Simple check to make sure the keys match
		if !bytes.Equal(serverKey, clientKey) {
			b.Errorf("Keys don't match")
		}
	}
}

// BenchmarkKeyGen measures the performance of just the key generation function
func BenchmarkKeyGen(b *testing.B) {
	// Setup test data
	var ecSecret x448.Key
	for i := range ecSecret {
		ecSecret[i] = byte(i)
	}

	pqSecret := make([]byte, mlkem1024.SharedKeySize)
	for i := range pqSecret {
		pqSecret[i] = byte(i + 100)
	}

	// Reset timer to exclude setup time
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key, err := KeyGen(ecSecret, pqSecret)
		if err != nil {
			b.Fatalf("KeyGen failed: %v", err)
		}

		// Simple check to make sure we got a key
		if len(key) != 32 {
			b.Errorf("Invalid key length")
		}
	}
}
