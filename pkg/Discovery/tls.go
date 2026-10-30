package discovery

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"uuid"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
)

// NewServerTLSConfig issues a fresh server certificate from ca for the given
// names and returns a TLS config that requires client certificates from ca.
// Clients must reach the server by one of hostnames or ips.
func NewServerTLSConfig(ca *certs.CertificateAuthority, hostnames []string, ips []net.IP) (*tls.Config, error) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	der, err := ca.IssueServerCertificate(key.PublicKey(), uuid.NewV7().String(), hostnames, ips)
	if err != nil {
		return nil, fmt.Errorf("issue server certificate: %w", err)
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca.Certificate)
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der, ca.Certificate.Raw},
			PrivateKey:  key,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
	}, nil
}
