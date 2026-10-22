package certs

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// File names used for a certificate authority stored on disk.
const (
	CACertificateFile = "ca.crt"
	CAPrivateKeyFile  = "ca.key"
)

const (
	pemTypeCertificate = "CERTIFICATE"
	pemTypePrivateKey  = "PRIVATE KEY"
)

// EncodeCertificatePEM encodes a DER certificate as PEM.
func EncodeCertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
}

// EncodePrivateKeyPEM encodes an ML-DSA private key as PKCS #8 PEM.
func EncodePrivateKeyPEM(key *mldsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der}), nil
}

// ParseCertificatePEM parses the first PEM certificate in data.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemTypeCertificate {
		return nil, errors.New("no PEM certificate found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParsePrivateKeyPEM parses a PKCS #8 PEM ML-DSA private key.
func ParsePrivateKeyPEM(data []byte) (*mldsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemTypePrivateKey {
		return nil, errors.New("no PEM private key found")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	key, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not ML-DSA", parsed)
	}
	return key, nil
}

// LoadCertificateFile reads a PEM certificate from path.
func LoadCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := ParseCertificatePEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cert, nil
}

// LoadPrivateKeyFile reads a PEM ML-DSA private key from path.
func LoadPrivateKeyFile(path string) (*mldsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// WriteCertificateFile writes a DER certificate to path as PEM.
func WriteCertificateFile(path string, der []byte) error {
	return writeNewFile(path, EncodeCertificatePEM(der), 0o644)
}

// WritePrivateKeyFile writes key to path as PEM, readable only by the owner.
func WritePrivateKeyFile(path string, key *mldsa.PrivateKey) error {
	data, err := EncodePrivateKeyPEM(key)
	if err != nil {
		return err
	}
	return writeNewFile(path, data, 0o600)
}

// writeNewFile refuses to overwrite so key material is never silently replaced.
func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Save writes the CA certificate and private key into dir.
func (ca *CertificateAuthority) Save(dir string) error {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := WritePrivateKeyFile(filepath.Join(dir, CAPrivateKeyFile), ca.PrivateKey); err != nil {
		return err
	}
	return WriteCertificateFile(filepath.Join(dir, CACertificateFile), ca.Certificate.Raw)
}

// LoadCertificateAuthority reads a CA previously written by Save.
func LoadCertificateAuthority(dir string) (*CertificateAuthority, error) {
	cert, err := LoadCertificateFile(filepath.Join(dir, CACertificateFile))
	if err != nil {
		return nil, err
	}
	key, err := LoadPrivateKeyFile(filepath.Join(dir, CAPrivateKeyFile))
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("certificate is not a CA certificate")
	}
	if !key.PublicKey().Equal(cert.PublicKey) {
		return nil, errors.New("CA private key does not match CA certificate")
	}

	ca := newCertificateAuthority(key, cert.NotBefore, cert.NotAfter)
	ca.Certificate = cert
	return ca, nil
}
