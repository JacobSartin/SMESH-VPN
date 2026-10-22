package main

import (
	"io"
	"path/filepath"
	"testing"
	"uuid"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

func TestInitCAThenIssueClientProducesLoadableIdentity(t *testing.T) {
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")
	clientDir := filepath.Join(root, "alice")
	id := uuid.NewV7()

	if err := runInitCA([]string{"-dir", caDir}, io.Discard); err != nil {
		t.Fatalf("init-ca: %v", err)
	}
	if err := runIssueClient([]string{"-ca-dir", caDir, "-out", clientDir, "-id", id.String()}, io.Discard); err != nil {
		t.Fatalf("issue-client: %v", err)
	}

	identity, err := session.LoadClientIdentity(
		filepath.Join(clientDir, clientCertificateFile),
		filepath.Join(clientDir, clientPrivateKeyFile),
		filepath.Join(clientDir, certs.CACertificateFile),
	)
	if err != nil {
		t.Fatalf("load issued identity: %v", err)
	}
	if identity.ID != id {
		t.Fatalf("identity ID %s, want %s", identity.ID, id)
	}

	if err := runInitCA([]string{"-dir", caDir}, io.Discard); err == nil {
		t.Fatal("expected init-ca to refuse to overwrite an existing CA")
	}
	if err := runIssueClient([]string{"-ca-dir", caDir, "-out", clientDir}, io.Discard); err == nil {
		t.Fatal("expected issue-client to refuse to overwrite existing client files")
	}
}
