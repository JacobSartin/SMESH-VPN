# Post-Quantum X Diffie-Hellman (PQXDH)

## Overview

PQXDH is a hybrid key exchange mechanism that combines classical elliptic curve cryptography with post-quantum cryptography to provide security that is resistant to both conventional and quantum computer attacks. This implementation is a critical component of SMESH-VPN, providing forward secrecy and quantum-resistant secure communications.

The target security level is 128 bit to match AES 256 taking into account Grover's algorithm. It is unnecessary to target a higher level of security and it would come at the cost of requiring more packets for the handshake. MLKEM requires a significant amount of data, 1088 bytes of ciphertext and 1184 bytes for the encapsulation key with MLKEM768. Using MLKEM1024 would already be over the limit of 1500 bytes which is the standard MTU and that is not accounting for any of the other necessary information.

## How It Works

PQXDH implements a hybrid approach with two main components:

1. **Classical Cryptography**: Uses X25519 elliptic curve Diffie-Hellman (ECDH) for traditional key exchange
2. **Post-Quantum Cryptography**: Uses ML-KEM-768 (Kyber) for quantum-resistant key encapsulation

By combining both methods, we achieve:

- Protection against current threats using well-established classical cryptography
- Protection against future quantum threats using post-quantum cryptography
- An attacker must break both systems to compromise the key

## Key Components

### Client & Server

The implementation includes dedicated client and server components:

- **PQXDHClient**: Manages both EC and PQ key pairs, handles key generation and response to server encapsulation, initiates handshake
- **PQXDHServer**: Primarily manages EC key pairs and handles encapsulation for the client's public keys

### Key Exchange Process

The key exchange follows these steps:

1. The client:

   - generates both EC and PQ key pairs
   - sends the public keys to the server

2. The server:

   - Generates its own EC key pair
   - Computes a shared EC secret using ECDH with the client's EC public key
   - Encapsulates a PQ shared secret using the client's PQ public key
   - Combines both secrets to derive the final session key
   - Returns its EC public key and the PQ ciphertext to the client

3. The client:
   - Computes the EC shared secret using ECDH with the server's EC public key
   - Decapsulates the PQ shared secret from the received ciphertext
   - Combines both secrets to derive the same final session key

The resulting shared key is then used for symmetric encryption in the VPN tunnel.

## Security Features

- **Forward Secrecy**: New session keys for each connection
- **Quantum Resistance**: Protected against attacks from quantum computers
- **Defense in Depth**: Requires breaking both classical and quantum-resistant algorithms
- **Standards Based**: Uses standard Go crypto library

## Implementation Details

This implementation uses the standard Go crypto libraries:

- `crypto/ecdh` for X25519 elliptic curve operations
- `crypto/mlkem` for ML-KEM post-quantum operations
- HKDF with SHA-512 for key derivation

## Usage Example

```go
// Client side
client := pqxdh.NewPQXDHClient()

// Server side
server := pqxdh.NewPQXDHServer()

// Server performs key exchange with client's public keys
serverKey, ciphertext, err := pqxdh.ServerKeyExchange(
    client.GetPQPublicKey(),
    client.GetECPublicKey(),
    *server
)

// Client completes key exchange with server's public key and ciphertext
clientKey, err := pqxdh.ClientKeyExchange(
    server.GetECPublicKey(),
    ciphertext,
    *client
)

// Both sides now have the same shared key
// serverKey == clientKey
```

## Testing

Comprehensive tests are included to verify:

- Key generation consistency
- Successful key exchange
- Error handling
- Performance benchmarks

Run tests with:

```bash
go test -v ./pkg/PQXDH
```

## References

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization)
- [ML-KEM (Kyber) Algorithm Specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
- [X25519 Key Exchange](https://datatracker.ietf.org/doc/html/rfc7748)
