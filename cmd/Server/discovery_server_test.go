package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
	"uuid"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

func TestDiscoveryServerRegisterListGetRemovePeer(t *testing.T) {
	discovery := newTestDiscoveryServer(t)

	peerA := uuid.New()
	peerB := uuid.New()

	_, err := discovery.RegisterPeer(peerA, mustAddrPort(t, "10.0.0.2:9000"))
	if err != nil {
		t.Fatalf("register peer A failed: %v", err)
	}
	if _, err := discovery.RegisterPeer(peerB, mustAddrPort(t, "10.0.0.3:9000")); err != nil {
		t.Fatalf("register peer B failed: %v", err)
	}

	peers := discovery.ListPeers(peerA)
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer after excluding peer A, got %d", len(peers))
	}
	if peers[0].ID != peerB {
		t.Fatalf("expected peer B, got %s", peers[0].ID)
	}

	record, exists := discovery.GetPeer(peerA)
	if !exists {
		t.Fatal("expected peer A to exist")
	}
	if record.Address != mustAddrPort(t, "10.0.0.2:9000") {
		t.Fatalf("expected peer A address, got %q", record.Address)
	}

	if err := discovery.RemovePeer(peerA); err != nil {
		t.Fatalf("remove peer A: %v", err)
	}
	if _, exists := discovery.GetPeer(peerA); exists {
		t.Fatal("peer A still exists after removal")
	}
}

func TestDiscoveryServerRejectsInvalidRegistration(t *testing.T) {
	discovery := newTestDiscoveryServer(t)

	if _, err := discovery.RegisterPeer(uuid.Nil(), mustAddrPort(t, "10.0.0.2:9000")); err != errInvalidPeerID {
		t.Fatalf("expected errInvalidPeerID, got %v", err)
	}
	if _, err := discovery.RegisterPeer(uuid.New(), netip.AddrPort{}); err != errInvalidPeerAddress {
		t.Fatalf("expected errInvalidPeerAddress, got %v", err)
	}
}

func TestDiscoveryServerCleansExpiredPeers(t *testing.T) {
	discovery := newTestDiscoveryServer(t)
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	discovery.now = func() time.Time { return now }

	oldPeer := uuid.New()
	activePeer := uuid.New()

	if _, err := discovery.RegisterPeer(oldPeer, mustAddrPort(t, "10.0.0.2:9000")); err != nil {
		t.Fatalf("register old peer failed: %v", err)
	}

	now = now.Add(3 * time.Minute)
	if _, err := discovery.RegisterPeer(activePeer, mustAddrPort(t, "10.0.0.3:9000")); err != nil {
		t.Fatalf("register active peer failed: %v", err)
	}

	peers := discovery.ListPeers(uuid.Nil())
	if len(peers) != 1 {
		t.Fatalf("expected only active peer after cleanup, got %d", len(peers))
	}
	if peers[0].ID != activePeer {
		t.Fatalf("expected active peer, got %s", peers[0].ID)
	}
}

func TestDiscoveryServerGetPeerRejectsExpiredPeer(t *testing.T) {
	discovery := newTestDiscoveryServer(t)
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	discovery.now = func() time.Time { return now }
	peerID := uuid.New()

	if _, err := discovery.RegisterPeer(peerID, mustAddrPort(t, "10.0.0.2:9000")); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	now = now.Add(3 * time.Minute)

	if _, exists := discovery.GetPeer(peerID); exists {
		t.Fatal("expired peer was returned by GetPeer")
	}
	if _, err := discovery.RegisterPeer(peerID, mustAddrPort(t, "10.0.0.2:9001")); err != nil {
		t.Fatalf("expected expired peer ID to be reusable: %v", err)
	}
}

func TestDiscoveryServerRemovePeer(t *testing.T) {
	discovery := newTestDiscoveryServer(t)
	peerID := uuid.New()
	if _, err := discovery.RegisterPeer(peerID, mustAddrPort(t, "10.0.0.2:9000")); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	if err := discovery.RemovePeer(peerID); err != nil {
		t.Fatalf("remove peer: %v", err)
	}
}

func TestDiscoveryHTTPUsesCertificateIdentity(t *testing.T) {
	discovery := newTestDiscoveryServer(t)
	peerID := uuid.New()
	peerCert := issueClientCertificate(t, discovery.ca, peerID)
	attackerCert := issueClientCertificate(t, discovery.ca, uuid.New())

	record := postPeer(t, discovery, peerCert, "10.0.0.2:9000")
	if record.ID != peerID {
		t.Fatalf("registration used %s instead of certificate ID %s", record.ID, peerID)
	}

	resp := servePeerRequest(t, discovery, nil, http.MethodDelete, "/peers", nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated delete status 401, got %d", resp.Code)
	}
	resp = servePeerRequest(t, discovery, attackerCert, http.MethodDelete, "/peers", nil)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected unregistered certificate delete status 404, got %d", resp.Code)
	}
	if _, exists := discovery.GetPeer(peerID); !exists {
		t.Fatal("request by a different certificate removed peer")
	}
	resp = servePeerRequest(t, discovery, peerCert, http.MethodDelete, "/peers", nil)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected owner certificate delete status 204, got %d", resp.Code)
	}
}

func TestDiscoveryHTTPRegisterListGetDelete(t *testing.T) {
	discovery := newTestDiscoveryServer(t)
	peerID := uuid.New()
	peerCert := issueClientCertificate(t, discovery.ca, peerID)
	record := postPeer(t, discovery, peerCert, "10.0.0.2:9000")
	if record.ID != peerID {
		t.Fatalf("expected registered peer ID %s, got %s", peerID, record.ID)
	}

	resp := servePeerRequest(t, discovery, peerCert, http.MethodGet, "/peers", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected list status 200, got %d", resp.Code)
	}

	var peers []PeerRecord
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatalf("decode peers failed: %v", err)
	}
	if len(peers) != 1 || peers[0].ID != peerID {
		t.Fatalf("expected registered peer in list, got %+v", peers)
	}

	resp = servePeerRequest(t, discovery, peerCert, http.MethodGet, "/peers/"+peerID.String(), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected get status 200, got %d", resp.Code)
	}

	resp = servePeerRequest(t, discovery, peerCert, http.MethodDelete, "/peers", nil)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected delete status 204, got %d", resp.Code)
	}
}

func postPeer(t *testing.T, discovery *DiscoveryServer, cert *x509.Certificate, address string) PeerRecord {
	t.Helper()

	payload, err := json.Marshal(peerRegistrationRequest{Address: mustAddrPort(t, address)})
	if err != nil {
		t.Fatalf("marshal peer registration failed: %v", err)
	}

	resp := servePeerRequest(t, discovery, cert, http.MethodPost, "/peers", bytes.NewReader(payload))
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected register status 201, got %d: %s", resp.Code, resp.Body.String())
	}

	var record PeerRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		t.Fatalf("decode registered peer failed: %v", err)
	}
	return record
}

func servePeerRequest(t *testing.T, discovery *DiscoveryServer, cert *x509.Certificate, method, target string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody io.Reader = http.NoBody
	if body != nil {
		requestBody = body
	}
	req := httptest.NewRequest(method, target, requestBody)
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	resp := httptest.NewRecorder()
	discovery.Handler().ServeHTTP(resp, req)
	return resp
}

func issueClientCertificate(t *testing.T, ca *certs.CertificateAuthority, id uuid.UUID) *x509.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	der, err := ca.IssueClientCertificate(key.PublicKey(), id.String())
	if err != nil {
		t.Fatalf("issue client certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse client certificate: %v", err)
	}
	return cert
}

func mustAddrPort(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		t.Fatalf("parse test address %q: %v", value, err)
	}
	return address
}

func newTestDiscoveryServer(t *testing.T) *DiscoveryServer {
	t.Helper()

	manager := session.NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	t.Cleanup(manager.Shutdown)
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("create certificate authority: %v", err)
	}
	return NewDiscoveryServer(manager, ca, 2*time.Minute)
}
