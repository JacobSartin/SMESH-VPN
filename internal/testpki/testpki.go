// Package testpki creates throwaway CAs and client identities for tests.
package testpki

import (
	"crypto/mldsa"
	"crypto/x509"
	"testing"
	"uuid"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

// NewCA returns a fresh in-memory certificate authority.
func NewCA(t testing.TB) *certs.CertificateAuthority {
	t.Helper()
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	return ca
}

// NewIdentity issues a client certificate from ca and returns it as an identity.
func NewIdentity(t testing.TB, ca *certs.CertificateAuthority) *session.ClientIdentity {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	der, err := ca.IssueClientCertificate(key.PublicKey(), uuid.NewV7().String())
	if err != nil {
		t.Fatalf("issue client certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse client certificate: %v", err)
	}
	identity, err := session.NewAuthenticatedClientIdentity(cert, key, ca.Certificate)
	if err != nil {
		t.Fatalf("build identity: %v", err)
	}
	return identity
}
