```text
███████╗███╗   ███╗███████╗███████╗██╗  ██╗    ██╗   ██╗██████╗ ███╗   ██╗
██╔════╝████╗ ████║██╔════╝██╔════╝██║  ██║    ██║   ██║██╔══██╗████╗  ██║
███████╗██╔████╔██║█████╗  ███████╗███████║    ██║   ██║██████╔╝██╔██╗ ██║
╚════██║██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║    ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
███████║██║ ╚═╝ ██║███████╗███████║██║  ██║     ╚████╔╝ ██║     ██║ ╚████║
╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝      ╚═══╝  ╚═╝     ╚═╝  ╚═══╝

Post-Quantum Secure Mesh VPN Client
-----------------------------------
```

A secure mesh VPN with Post-Quantum Cryptography.

## Features

- Post-quantum secure key exchange using hybrid classical/post-quantum cryptography
- End-to-end encrypted communication between nodes
- Mesh topology allowing direct peer-to-peer connections
- Certificate-based identity system for secure authentication
- Protection against MITM attacks during key exchange
- Automatic peer discovery through a central discovery server

## Requirements

- Go 1.20+ (developed with Go 1.24)
- For TUN/TAP interface: Appropriate drivers for your OS

## Installation

1. Clone the repository:

```bash
git clone https://github.com/JacobSartin/SMESH-VPN.git
cd SMESH-VPN
```

2. Build the binaries:

```bash
# If using Windows with WSL for Make
wsl make

# If using native Make
make
```

This will create both client and server binaries for Windows and Linux in the `bin/` directory.

## Certificate Setup

SMESH-VPN uses certificate-based authentication to ensure that only authorized clients can connect to the network and to protect against MITM attacks.

(Certificate management functionality is in development.)

## Running the Discovery Server

Start the discovery server:

```bash
# Linux
./bin/smesh-server_linux_amd64.exe

# Windows
.\bin\smesh-server_windows_amd64.exe
```

## Running a Client

Start a VPN client:

```bash
# Linux
./bin/smesh-client_linux_amd64.exe

# Windows
.\bin\smesh-client_windows_amd64.exe
```

Configuration options will be available through command line flags or a configuration file.

## Security Considerations

- The certificates are used to authenticate clients during connection establishment
- All key exchanges are protected against MITM attacks
- Only authorized clients with valid certificates can connect to the VPN
- The discovery server validates client certificates before allowing connections
- All data exchanged between peers is end-to-end encrypted

## Docker Support

You can also run the VPN components in Docker:

```bash
docker-compose up -d
```

## Testing

Run the tests:

```bash
# Run all tests
go test ./...

# Run tests for a specific package
go test ./pkg/PQXDH

# Run tests with coverage
go test -cover ./...
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
