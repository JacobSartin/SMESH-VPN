package certs

import (
	"crypto/mldsa"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"
	"uuid"
)

func TestCertificateAuthoritySaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	original, err := NewCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Save(dir); err != nil {
		t.Fatalf("save CA: %v", err)
	}

	loaded, err := LoadCertificateAuthority(dir)
	if err != nil {
		t.Fatalf("load CA: %v", err)
	}
	if !loaded.Certificate.Equal(original.Certificate) {
		t.Fatal("loaded CA certificate differs from saved one")
	}

	// A certificate issued by the loaded CA must chain to the original CA certificate.
	clientKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	der, err := loaded.IssueClientCertificate(clientKey.PublicKey(), id.String())
	if err != nil {
		t.Fatalf("issue from loaded CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := original.ValidateClientCertificate(cert); !valid || err != nil {
		t.Fatalf("certificate from loaded CA rejected by original: %v", err)
	}
	if got, err := ClientIDFromCertificate(cert); err != nil || got != id {
		t.Fatalf("client ID = %s, %v; want %s", got, err, id)
	}
}

func TestCertificateAuthoritySaveRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	first, _ := NewCertificateAuthority()
	second, _ := NewCertificateAuthority()
	if err := first.Save(dir); err != nil {
		t.Fatal(err)
	}
	if err := second.Save(dir); err == nil {
		t.Fatal("expected saving over an existing CA to fail")
	}
}

func TestLoadCertificateAuthorityRejectsMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCertificateAuthority()
	if err := WriteCertificateFile(filepath.Join(dir, CACertificateFile), ca.Certificate.Raw); err != nil {
		t.Fatal(err)
	}
	otherKey, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	if err := WritePrivateKeyFile(filepath.Join(dir, CAPrivateKeyFile), otherKey); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertificateAuthority(dir); err == nil {
		t.Fatal("expected mismatched CA key to be rejected")
	}
}

func TestIssuedSerialNumbersAreUniqueAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCertificateAuthority()
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 3 {
		loaded, err := LoadCertificateAuthority(dir)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := mldsa.GenerateKey(mldsa.MLDSA44())
		der, err := loaded.IssueClientCertificate(key.PublicKey(), uuid.New().String())
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		serial := cert.SerialNumber.String()
		if seen[serial] {
			t.Fatalf("serial %s issued twice", serial)
		}
		seen[serial] = true
	}
}

func TestIssuedRecordsPreventDuplicateClientIDsAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCertificateAuthority()
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	id := uuid.New().String()

	first, err := LoadCertificateAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	der, err := first.IssueClientCertificate(key.PublicKey(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordIssuedCertificate(dir, der); err != nil {
		t.Fatalf("record issued certificate: %v", err)
	}
	if err := RecordIssuedCertificate(dir, der); !errors.Is(err, ErrCertificateAlreadyExists) {
		t.Fatalf("recording the same client twice: expected ErrCertificateAlreadyExists, got %v", err)
	}

	second, err := LoadCertificateAuthority(dir)
	if err != nil {
		t.Fatalf("reload CA with issued records: %v", err)
	}
	otherKey, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	if _, err := second.IssueClientCertificate(otherKey.PublicKey(), id); !errors.Is(err, ErrCertificateAlreadyExists) {
		t.Fatalf("reissuing a recorded client ID: expected ErrCertificateAlreadyExists, got %v", err)
	}
}

func TestLoadCertificateAuthorityRejectsForeignIssuedRecord(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCertificateAuthority()
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	other, _ := NewCertificateAuthority()
	key, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	der, err := other.IssueClientCertificate(key.PublicKey(), uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordIssuedCertificate(dir, der); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertificateAuthority(dir); err == nil {
		t.Fatal("expected a record signed by another CA to be rejected")
	}
}
