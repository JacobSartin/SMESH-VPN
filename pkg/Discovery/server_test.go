package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
	"uuid"

	"github.com/JacobSartin/SMESH-VPN/internal/testpki"
	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

func TestRegistryRegisterListGetRemove(t *testing.T) {
	ds := NewServer(testpki.NewCA(t), 2*time.Minute)
	peerA, peerB := uuid.New(), uuid.New()

	mustRegister(t, ds, peerA, "198.51.100.2:7777", "10.77.0.2")
	mustRegister(t, ds, peerB, "198.51.100.3:7777", "10.77.0.3")

	if peers := ds.ListPeers(uuid.Nil()); len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	others := ds.ListPeers(peerA)
	if len(others) != 1 || others[0].ID != peerB {
		t.Fatalf("expected only peer B when excluding A, got %+v", others)
	}

	record, ok := ds.GetPeer(peerA)
	if !ok || record.Address != netip.MustParseAddrPort("198.51.100.2:7777") || record.VPNIP != netip.MustParseAddr("10.77.0.2") {
		t.Fatalf("unexpected record for peer A: %+v (found %v)", record, ok)
	}

	if err := ds.RemovePeer(peerA); err != nil {
		t.Fatalf("remove peer A: %v", err)
	}
	if _, ok := ds.GetPeer(peerA); ok {
		t.Fatal("peer A still exists after removal")
	}
	if err := ds.RemovePeer(peerA); !errors.Is(err, errPeerNotFound) {
		t.Fatalf("expected errPeerNotFound removing twice, got %v", err)
	}
}

func TestRegistryRejectsInvalidRegistration(t *testing.T) {
	ds := NewServer(testpki.NewCA(t), 2*time.Minute)
	good := netip.MustParseAddrPort("198.51.100.2:7777")
	vpnIP := netip.MustParseAddr("10.77.0.2")

	cases := []struct {
		name    string
		id      uuid.UUID
		address netip.AddrPort
		vpnIP   netip.Addr
		want    error
	}{
		{"nil id", uuid.Nil(), good, vpnIP, errInvalidPeerID},
		{"missing address", uuid.New(), netip.AddrPort{}, vpnIP, errInvalidPeerAddress},
		{"zero port", uuid.New(), netip.MustParseAddrPort("198.51.100.2:0"), vpnIP, errInvalidPeerAddress},
		{"unspecified host", uuid.New(), netip.MustParseAddrPort("0.0.0.0:7777"), vpnIP, errInvalidPeerAddress},
		{"missing vpn ip", uuid.New(), good, netip.Addr{}, errInvalidVPNIP},
		{"ipv6 vpn ip", uuid.New(), good, netip.MustParseAddr("fd00::2"), errInvalidVPNIP},
		{"loopback vpn ip", uuid.New(), good, netip.MustParseAddr("127.0.0.2"), errInvalidVPNIP},
	}
	for _, tc := range cases {
		if _, err := ds.RegisterPeer(tc.id, tc.address, tc.vpnIP); !errors.Is(err, tc.want) {
			t.Errorf("%s: expected %v, got %v", tc.name, tc.want, err)
		}
	}
}

func TestRegistryVPNIPConflicts(t *testing.T) {
	ds := NewServer(testpki.NewCA(t), 2*time.Minute)
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	ds.now = func() time.Time { return now }
	peerA, peerB := uuid.New(), uuid.New()

	mustRegister(t, ds, peerA, "198.51.100.2:7777", "10.77.0.2")
	// Refreshing your own registration with the same VPN IP is fine.
	mustRegister(t, ds, peerA, "198.51.100.2:7777", "10.77.0.2")

	_, err := ds.RegisterPeer(peerB, netip.MustParseAddrPort("198.51.100.3:7777"), netip.MustParseAddr("10.77.0.2"))
	if !errors.Is(err, errVPNIPInUse) {
		t.Fatalf("expected errVPNIPInUse, got %v", err)
	}

	// Once peer A expires its VPN IP can be claimed.
	now = now.Add(3 * time.Minute)
	mustRegister(t, ds, peerB, "198.51.100.3:7777", "10.77.0.2")
}

func TestRegistryExpiresPeers(t *testing.T) {
	ds := NewServer(testpki.NewCA(t), 2*time.Minute)
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	ds.now = func() time.Time { return now }
	oldPeer, activePeer := uuid.New(), uuid.New()

	mustRegister(t, ds, oldPeer, "198.51.100.2:7777", "10.77.0.2")
	now = now.Add(3 * time.Minute)
	mustRegister(t, ds, activePeer, "198.51.100.3:7777", "10.77.0.3")

	peers := ds.ListPeers(uuid.Nil())
	if len(peers) != 1 || peers[0].ID != activePeer {
		t.Fatalf("expected only the active peer, got %+v", peers)
	}
	if _, ok := ds.GetPeer(oldPeer); ok {
		t.Fatal("expired peer was returned by GetPeer")
	}
}

func TestHandlerRequiresValidCertificate(t *testing.T) {
	ds := NewServer(testpki.NewCA(t), 2*time.Minute)
	outsider := testpki.NewIdentity(t, testpki.NewCA(t))

	if resp := serve(t, ds, nil, http.MethodGet, "/peers", nil); resp.Code != http.StatusUnauthorized {
		t.Fatalf("no certificate: expected 401, got %d", resp.Code)
	}
	if resp := serve(t, ds, outsider.Certificate, http.MethodGet, "/peers", nil); resp.Code != http.StatusUnauthorized {
		t.Fatalf("certificate from another CA: expected 401, got %d", resp.Code)
	}
}

func TestHandlerUsesCertificateIdentity(t *testing.T) {
	ca := testpki.NewCA(t)
	ds := NewServer(ca, 2*time.Minute)
	owner := testpki.NewIdentity(t, ca)
	other := testpki.NewIdentity(t, ca)

	record := registerViaHandler(t, ds, owner.Certificate, "198.51.100.2:7777", "10.77.0.2")
	if record.ID != owner.ID {
		t.Fatalf("registration used %s instead of certificate ID %s", record.ID, owner.ID)
	}

	// Another certificate cannot remove the owner's registration: DELETE always targets the caller.
	if resp := serve(t, ds, other.Certificate, http.MethodDelete, "/peers", nil); resp.Code != http.StatusNotFound {
		t.Fatalf("delete by unregistered certificate: expected 404, got %d", resp.Code)
	}
	if _, ok := ds.GetPeer(owner.ID); !ok {
		t.Fatal("request by a different certificate removed the owner's registration")
	}

	// The caller is excluded from its own listing.
	var listed []PeerRecord
	decode(t, serve(t, ds, owner.Certificate, http.MethodGet, "/peers", nil), &listed)
	if len(listed) != 0 {
		t.Fatalf("owner should not see itself, got %+v", listed)
	}
	decode(t, serve(t, ds, other.Certificate, http.MethodGet, "/peers", nil), &listed)
	if len(listed) != 1 || listed[0].ID != owner.ID {
		t.Fatalf("other should see the owner, got %+v", listed)
	}

	if resp := serve(t, ds, other.Certificate, http.MethodGet, "/peers/"+owner.ID.String(), nil); resp.Code != http.StatusOK {
		t.Fatalf("get peer by ID: expected 200, got %d", resp.Code)
	}
	if resp := serve(t, ds, owner.Certificate, http.MethodDelete, "/peers", nil); resp.Code != http.StatusNoContent {
		t.Fatalf("owner delete: expected 204, got %d", resp.Code)
	}
}

func TestHandlerFillsUnspecifiedAddressFromSource(t *testing.T) {
	ca := testpki.NewCA(t)
	ds := NewServer(ca, 2*time.Minute)
	peer := testpki.NewIdentity(t, ca)

	record := registerViaHandler(t, ds, peer.Certificate, "0.0.0.0:7777", "10.77.0.2")
	// httptest.NewRequest uses 192.0.2.1 as the remote address.
	if want := netip.MustParseAddrPort("192.0.2.1:7777"); record.Address != want {
		t.Fatalf("expected address %s, got %s", want, record.Address)
	}
}

func TestHandlerReportsVPNIPConflict(t *testing.T) {
	ca := testpki.NewCA(t)
	ds := NewServer(ca, 2*time.Minute)
	first := testpki.NewIdentity(t, ca)
	second := testpki.NewIdentity(t, ca)

	registerViaHandler(t, ds, first.Certificate, "198.51.100.2:7777", "10.77.0.2")
	body, _ := json.Marshal(RegistrationRequest{
		Address: netip.MustParseAddrPort("198.51.100.3:7777"),
		VPNIP:   netip.MustParseAddr("10.77.0.2"),
	})
	if resp := serve(t, ds, second.Certificate, http.MethodPost, "/peers", body); resp.Code != http.StatusConflict {
		t.Fatalf("expected 409 for a VPN IP in use, got %d", resp.Code)
	}
}

// TestClientOverMutualTLS exercises the real TLS stack with ML-DSA certificates.
func TestClientOverMutualTLS(t *testing.T) {
	ca := testpki.NewCA(t)
	url := startTLSServer(t, NewServer(ca, 2*time.Minute))
	alice := testpki.NewIdentity(t, ca)
	bob := testpki.NewIdentity(t, ca)
	ctx := context.Background()

	aliceClient := mustClient(t, url, alice)
	bobClient := mustClient(t, url, bob)

	record, err := aliceClient.Register(ctx, netip.MustParseAddrPort("0.0.0.0:7777"), netip.MustParseAddr("10.77.0.2"))
	if err != nil {
		t.Fatalf("alice register: %v", err)
	}
	if record.ID != alice.ID || record.Address != netip.MustParseAddrPort("127.0.0.1:7777") {
		t.Fatalf("unexpected registration %+v", record)
	}
	if _, err := bobClient.Register(ctx, netip.MustParseAddrPort("0.0.0.0:7778"), netip.MustParseAddr("10.77.0.3")); err != nil {
		t.Fatalf("bob register: %v", err)
	}

	peers, err := aliceClient.ListPeers(ctx)
	if err != nil {
		t.Fatalf("alice list: %v", err)
	}
	if len(peers) != 1 || peers[0].ID != bob.ID || peers[0].VPNIP != netip.MustParseAddr("10.77.0.3") {
		t.Fatalf("alice expected to see only bob, got %+v", peers)
	}

	_, err = bobClient.Register(ctx, netip.MustParseAddrPort("0.0.0.0:7778"), netip.MustParseAddr("10.77.0.2"))
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 StatusError, got %v", err)
	}

	if err := aliceClient.Deregister(ctx); err != nil {
		t.Fatalf("alice deregister: %v", err)
	}
	if peers, _ := bobClient.ListPeers(ctx); len(peers) != 0 {
		t.Fatalf("bob still sees peers after alice deregistered: %+v", peers)
	}
}

func TestClientFromOtherCAIsRejected(t *testing.T) {
	ca := testpki.NewCA(t)
	url := startTLSServer(t, NewServer(ca, 2*time.Minute))

	// The outsider trusts the real CA (so the server certificate verifies) but
	// presents a certificate from a different CA.
	outsider := testpki.NewIdentity(t, testpki.NewCA(t))
	outsider.CACertificate = ca.Certificate
	if _, err := mustClient(t, url, outsider).ListPeers(context.Background()); err == nil {
		t.Fatal("expected a client certificate from another CA to be rejected")
	}
}

func TestHeartbeatRegistersUntilCancelled(t *testing.T) {
	ca := testpki.NewCA(t)
	ds := NewServer(ca, 2*time.Minute)
	url := startTLSServer(t, ds)
	peer := testpki.NewIdentity(t, ca)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mustClient(t, url, peer).Heartbeat(ctx, 20*time.Millisecond, netip.MustParseAddrPort("0.0.0.0:7777"), netip.MustParseAddr("10.77.0.2"), func(err error) { t.Errorf("heartbeat: %v", err) })
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for {
		if _, ok := ds.GetPeer(peer.ID); ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("heartbeat never registered the peer")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat did not stop after cancel")
	}
}

func mustRegister(t *testing.T, ds *Server, id uuid.UUID, address, vpnIP string) {
	t.Helper()
	if _, err := ds.RegisterPeer(id, netip.MustParseAddrPort(address), netip.MustParseAddr(vpnIP)); err != nil {
		t.Fatalf("register %s: %v", id, err)
	}
}

func registerViaHandler(t *testing.T, ds *Server, cert *x509.Certificate, address, vpnIP string) PeerRecord {
	t.Helper()
	body, err := json.Marshal(RegistrationRequest{Address: netip.MustParseAddrPort(address), VPNIP: netip.MustParseAddr(vpnIP)})
	if err != nil {
		t.Fatal(err)
	}
	resp := serve(t, ds, cert, http.MethodPost, "/peers", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var record PeerRecord
	decode(t, resp, &record)
	return record
}

// serve calls the handler directly with a fake TLS state carrying cert.
func serve(t *testing.T, ds *Server, cert *x509.Certificate, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	resp := httptest.NewRecorder()
	ds.Handler().ServeHTTP(resp, req)
	return resp
}

func decode(t *testing.T, resp *httptest.ResponseRecorder, out any) {
	t.Helper()
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func startTLSServer(t *testing.T, ds *Server) string {
	t.Helper()
	tlsConfig, err := NewServerTLSConfig(ds.ca, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(ds.Handler())
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

func mustClient(t *testing.T, url string, identity *session.ClientIdentity) *Client {
	t.Helper()
	client, err := NewClient(url, identity)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
