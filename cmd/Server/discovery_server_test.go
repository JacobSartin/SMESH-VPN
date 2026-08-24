package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
	"github.com/google/uuid"
)

func TestDiscoveryServerRegisterListGetRemovePeer(t *testing.T) {
	discovery := newTestDiscoveryServer(t)

	peerA := uuid.New()
	peerB := uuid.New()

	if _, err := discovery.RegisterPeer(peerA, "10.0.0.2:9000"); err != nil {
		t.Fatalf("register peer A failed: %v", err)
	}
	if _, err := discovery.RegisterPeer(peerB, "10.0.0.3:9000"); err != nil {
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
	if record.Address != "10.0.0.2:9000" {
		t.Fatalf("expected peer A address, got %q", record.Address)
	}

	if !discovery.RemovePeer(peerA) {
		t.Fatal("expected peer A removal to return true")
	}
	if _, exists := discovery.GetPeer(peerA); exists {
		t.Fatal("peer A still exists after removal")
	}
}

func TestDiscoveryServerRejectsInvalidRegistration(t *testing.T) {
	discovery := newTestDiscoveryServer(t)

	if _, err := discovery.RegisterPeer(uuid.Nil, "10.0.0.2:9000"); err != errInvalidPeerID {
		t.Fatalf("expected errInvalidPeerID, got %v", err)
	}
	if _, err := discovery.RegisterPeer(uuid.New(), " "); err != errInvalidPeerAddress {
		t.Fatalf("expected errInvalidPeerAddress, got %v", err)
	}
}

func TestDiscoveryServerCleansExpiredPeers(t *testing.T) {
	discovery := newTestDiscoveryServer(t)
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	discovery.now = func() time.Time { return now }

	oldPeer := uuid.New()
	activePeer := uuid.New()

	if _, err := discovery.RegisterPeer(oldPeer, "10.0.0.2:9000"); err != nil {
		t.Fatalf("register old peer failed: %v", err)
	}

	now = now.Add(3 * time.Minute)
	if _, err := discovery.RegisterPeer(activePeer, "10.0.0.3:9000"); err != nil {
		t.Fatalf("register active peer failed: %v", err)
	}

	peers := discovery.ListPeers(uuid.Nil)
	if len(peers) != 1 {
		t.Fatalf("expected only active peer after cleanup, got %d", len(peers))
	}
	if peers[0].ID != activePeer {
		t.Fatalf("expected active peer, got %s", peers[0].ID)
	}
}

func TestDiscoveryHTTPRegisterListGetDelete(t *testing.T) {
	discovery := newTestDiscoveryServer(t)
	server := httptest.NewServer(discovery.Handler())
	defer server.Close()

	peerID := uuid.New()
	record := postPeer(t, server.URL, peerID, "10.0.0.2:9000")
	if record.ID != peerID {
		t.Fatalf("expected registered peer ID %s, got %s", peerID, record.ID)
	}

	resp, err := http.Get(server.URL + "/peers")
	if err != nil {
		t.Fatalf("list peers failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected list status 200, got %d", resp.StatusCode)
	}

	var peers []PeerRecord
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatalf("decode peers failed: %v", err)
	}
	if len(peers) != 1 || peers[0].ID != peerID {
		t.Fatalf("expected registered peer in list, got %+v", peers)
	}

	resp, err = http.Get(server.URL + "/peers/" + peerID.String())
	if err != nil {
		t.Fatalf("get peer failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected get status 200, got %d", resp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/peers/"+peerID.String(), nil)
	if err != nil {
		t.Fatalf("create delete request failed: %v", err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete peer failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected delete status 204, got %d", resp.StatusCode)
	}
}

func postPeer(t *testing.T, baseURL string, id uuid.UUID, address string) PeerRecord {
	t.Helper()

	payload, err := json.Marshal(peerRegistrationRequest{ID: id, Address: address})
	if err != nil {
		t.Fatalf("marshal peer registration failed: %v", err)
	}

	resp, err := http.Post(baseURL+"/peers", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("post peer failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected register status 201, got %d", resp.StatusCode)
	}

	var record PeerRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		t.Fatalf("decode registered peer failed: %v", err)
	}

	return record
}

func newTestDiscoveryServer(t *testing.T) *DiscoveryServer {
	t.Helper()

	manager := session.NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	t.Cleanup(manager.Shutdown)
	return NewDiscoveryServer(manager, 2*time.Minute)
}
