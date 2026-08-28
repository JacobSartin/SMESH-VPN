package certs

import (
	"crypto/mldsa"
	"crypto/x509"
	"testing"
)

func TestCertificateChainAndCRLUseMLDSA44(t *testing.T) {
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	assertMLDSA44Certificate(t, ca.Certificate)

	clientKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.IssueClientCertificate(clientKey.PublicKey(), "post-quantum-client")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	assertMLDSA44Certificate(t, certificate)

	if err := ca.RevokeCertificate("post-quantum-client", 0); err != nil {
		t.Fatal(err)
	}
	crlDER, err := ca.GetCRL()
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if crl.SignatureAlgorithm != x509.MLDSA44 {
		t.Fatalf("CRL signature algorithm = %v, want ML-DSA-44", crl.SignatureAlgorithm)
	}
}

func assertMLDSA44Certificate(t *testing.T, certificate *x509.Certificate) {
	t.Helper()
	if certificate.SignatureAlgorithm != x509.MLDSA44 {
		t.Fatalf("certificate signature algorithm = %v, want ML-DSA-44", certificate.SignatureAlgorithm)
	}
	publicKey, ok := certificate.PublicKey.(*mldsa.PublicKey)
	if !ok || publicKey.Parameters() != mldsa.MLDSA44() {
		t.Fatalf("certificate public key = %T, want ML-DSA-44", certificate.PublicKey)
	}
}
