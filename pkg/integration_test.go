package smeshvpn

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/JacobSartin/SMESH-VPN/pkg/AES"
	"github.com/JacobSartin/SMESH-VPN/pkg/PQXDH"
)

// TestPQXDHToAESIntegration tests the complete flow:
// 1. PQXDH key exchange between client and server
// 2. Using the derived shared key to initialize AES encryption
// 3. Encrypting data with one peer and decrypting with the other
func TestPQXDHToAESIntegration(t *testing.T) {
	// Create client and server instances
	client := pqxdh.NewPQXDHClient()
	server := pqxdh.NewPQXDHServer()

	// Perform server-side key exchange
	serverKey, ciphertext, err := pqxdh.ServerKeyExchange(client.GetPQPublicKey(), client.GetECPublicKey(), *server)
	if err != nil {
		t.Fatalf("Server key exchange failed: %v", err)
	}

	// Perform client-side key exchange
	clientKey, err := pqxdh.ClientKeyExchange(server.GetECPublicKey(), ciphertext, *client)
	if err != nil {
		t.Fatalf("Client key exchange failed: %v", err)
	}

	// Verify that both parties derived the same key
	if !bytes.Equal(serverKey, clientKey) {
		t.Fatalf("Key exchange failed: server and client keys do not match")
	}

	// Initialize AES cipher with the derived keys
	serverAES, err := aes.NewAES256(serverKey)
	if err != nil {
		t.Fatalf("Failed to initialize server AES: %v", err)
	}
	defer serverAES.Close()

	clientAES, err := aes.NewAES256(clientKey)
	if err != nil {
		t.Fatalf("Failed to initialize client AES: %v", err)
	}
	defer clientAES.Close()

	// Test multiple data sizes
	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "Small message",
			plaintext: []byte("Hello, SMESH-VPN!"),
		},
		{
			name:      "Medium message",
			plaintext: bytes.Repeat([]byte("SMESH-VPN secure data transfer test. "), 20),
		},
		{
			name:      "Large message (simulating packet)",
			plaintext: make([]byte, 1500), // Typical MTU size
		},
	}

	// Initialize random data for the larger test case
	_, err = io.ReadFull(rand.Reader, testCases[2].plaintext)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Server encrypts message for client
			serverToClientMsg, err := serverAES.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Server encryption failed: %v", err)
			}

			// Client decrypts message from server
			decryptedByClient, err := clientAES.Decrypt(serverToClientMsg)
			if err != nil {
				t.Fatalf("Client decryption failed: %v", err)
			}

			// Verify client correctly decrypted the message
			if !bytes.Equal(decryptedByClient, tc.plaintext) {
				t.Errorf("Client decryption mismatch: expected %v, got %v", tc.plaintext, decryptedByClient)
			}

			// Client encrypts message for server
			clientToServerMsg, err := clientAES.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Client encryption failed: %v", err)
			}

			// Server decrypts message from client
			decryptedByServer, err := serverAES.Decrypt(clientToServerMsg)
			if err != nil {
				t.Fatalf("Server decryption failed: %v", err)
			}

			// Verify server correctly decrypted the message
			if !bytes.Equal(decryptedByServer, tc.plaintext) {
				t.Errorf("Server decryption mismatch: expected %v, got %v", tc.plaintext, decryptedByServer)
			}
		})
	}
}

// TestPQXDHToAESWithTamper tests what happens when messages are tampered with
func TestPQXDHToAESWithTamper(t *testing.T) {
	// Create client and server instances
	client := pqxdh.NewPQXDHClient()
	server := pqxdh.NewPQXDHServer()

	// Perform the key exchange
	serverKey, ciphertext, err := pqxdh.ServerKeyExchange(client.GetPQPublicKey(), client.GetECPublicKey(), *server)
	if err != nil {
		t.Fatalf("Server key exchange failed: %v", err)
	}

	clientKey, err := pqxdh.ClientKeyExchange(server.GetECPublicKey(), ciphertext, *client)
	if err != nil {
		t.Fatalf("Client key exchange failed: %v", err)
	}

	// Initialize AES cipher with the derived keys
	serverAES, err := aes.NewAES256(serverKey)
	if err != nil {
		t.Fatalf("Failed to initialize server AES: %v", err)
	}
	defer serverAES.Close()

	clientAES, err := aes.NewAES256(clientKey)
	if err != nil {
		t.Fatalf("Failed to initialize client AES: %v", err)
	}
	defer clientAES.Close()

	// Create test message
	plaintext := []byte("This message is confidential!")

	// Server encrypts message for client
	encrypted, err := serverAES.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper with the ciphertext (change a byte in the authenticated portion)
	tamperPos := len(encrypted) / 2
	encrypted[tamperPos] ^= 0x01 // Flip a bit

	// Client tries to decrypt the tampered message
	_, err = clientAES.Decrypt(encrypted)

	// We expect decryption to fail due to authentication failure
	if err == nil {
		t.Fatalf("Expected decryption to fail with tampered ciphertext, but it succeeded")
	}

	t.Logf("Correctly detected tampering with error: %v", err)
}

// BenchmarkPQXDHKeyExchange benchmarks the key exchange process
func BenchmarkPQXDHKeyExchange(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create client and server instances
		client := pqxdh.NewPQXDHClient()
		server := pqxdh.NewPQXDHServer()

		// Perform key exchange
		serverKey, ciphertext, err := pqxdh.ServerKeyExchange(client.GetPQPublicKey(), client.GetECPublicKey(), *server)
		if err != nil {
			b.Fatalf("Server key exchange failed: %v", err)
		}

		clientKey, err := pqxdh.ClientKeyExchange(server.GetECPublicKey(), ciphertext, *client)
		if err != nil {
			b.Fatalf("Client key exchange failed: %v", err)
		}

		// Ensure keys match
		if !bytes.Equal(serverKey, clientKey) {
			b.Fatalf("Keys don't match")
		}
	}
}

// BenchmarkFullProtocol benchmarks the combined protocol (key exchange + encryption + decryption)
func BenchmarkFullProtocol(b *testing.B) {
	// Prepare a 1KB packet for the benchmark
	packet := make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, packet)
	if err != nil {
		b.Fatalf("Failed to generate random packet: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create client and server instances
		client := pqxdh.NewPQXDHClient()
		server := pqxdh.NewPQXDHServer()

		// Perform key exchange
		serverKey, ciphertext, err := pqxdh.ServerKeyExchange(client.GetPQPublicKey(), client.GetECPublicKey(), *server)
		if err != nil {
			b.Fatalf("Server key exchange failed: %v", err)
		}

		clientKey, err := pqxdh.ClientKeyExchange(server.GetECPublicKey(), ciphertext, *client)
		if err != nil {
			b.Fatalf("Client key exchange failed: %v", err)
		}

		// Initialize AES cipher with the derived keys
		serverAES, err := aes.NewAES256(serverKey)
		if err != nil {
			b.Fatalf("Failed to initialize server AES: %v", err)
		}

		clientAES, err := aes.NewAES256(clientKey)
		if err != nil {
			b.Fatalf("Failed to initialize client AES: %v", err)
		}

		// Server encrypts data
		encrypted, err := serverAES.Encrypt(packet)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}

		// Client decrypts data
		decrypted, err := clientAES.Decrypt(encrypted)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}

		// Verify decryption
		if !bytes.Equal(decrypted, packet) {
			b.Fatalf("Decryption mismatch")
		}

		// Clean up
		serverAES.Close()
		clientAES.Close()
	}
}
