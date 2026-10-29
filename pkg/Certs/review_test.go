package certs

import (
	"crypto/mldsa"
	"crypto/x509"
	"errors"
	"testing"
)

// Test added during code review. A failing test here means the weakness it
// describes is present.

// Revocations are keyed by client ID rather than serial number. If a client is
// re-issued a certificate after revocation and that one is revoked too, the
// second entry overwrites the first and the original certificate silently
// becomes valid again on the next CRL regeneration.
func TestReissuedClientKeepsEarlierSerialRevoked(t *testing.T) {
	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}

	issue := func() *x509.Certificate {
		t.Helper()
		key, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			t.Fatal(err)
		}
		der, err := ca.IssueClientCertificate(key.PublicKey(), "client-1")
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	first := issue()
	if err := ca.RevokeCertificate("client-1", 1); err != nil {
		t.Fatal(err)
	}
	second := issue()
	if err := ca.RevokeCertificate("client-1", 1); err != nil {
		t.Fatal(err)
	}

	for name, cert := range map[string]*x509.Certificate{"first": first, "second": second} {
		_, err := ca.ValidateClientCertificate(cert)
		if !errors.Is(err, ErrCertificateRevoked) {
			t.Errorf("%s certificate (serial %s) should be revoked, got err=%v", name, cert.SerialNumber, err)
		}
	}
}
