package mesh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/JacobSartin/SMESH-VPN/internal/testpki"
	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	discovery "github.com/JacobSartin/SMESH-VPN/pkg/Discovery"
	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

// fakeDevice is an in-memory TUN device. Packets written to inject are returned
// by Read; packets the node writes appear on delivered.
type fakeDevice struct {
	inject    chan []byte
	delivered chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func newFakeDevice() *fakeDevice {
	return &fakeDevice{
		inject:    make(chan []byte, 16),
		delivered: make(chan []byte, 16),
		closed:    make(chan struct{}),
	}
}

func (d *fakeDevice) Read(p []byte) (int, error) {
	select {
	case packet := <-d.inject:
		return copy(p, packet), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *fakeDevice) Write(p []byte) (int, error) {
	packet := append([]byte(nil), p...)
	select {
	case d.delivered <- packet:
		return len(p), nil
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *fakeDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func (d *fakeDevice) Name() string { return "fake0" }
func (d *fakeDevice) MTU() int     { return 1400 }

type testPeer struct {
	identity *session.ClientIdentity
	vpnIP    netip.Addr
	device   *fakeDevice
	node     *Node
	cancel   context.CancelFunc
	done     chan error
	stopOnce sync.Once
	err      error
}

func startDiscovery(t *testing.T, ca *certs.CertificateAuthority) string {
	t.Helper()
	tlsConfig, err := discovery.NewServerTLSConfig(ca, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(discovery.NewServer(ca, time.Minute).Handler())
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

// startPeer issues a new identity and runs a peer with it.
func startPeer(t *testing.T, ca *certs.CertificateAuthority, discoveryURL string, vpnIP string) *testPeer {
	t.Helper()
	return runPeer(t, discoveryURL, testpki.NewIdentity(t, ca), netip.MustParseAddr(vpnIP))
}

// runPeer listens on a fresh loopback port, registers with discovery, and runs a node.
func runPeer(t *testing.T, discoveryURL string, identity *session.ClientIdentity, vpnIP netip.Addr) *testPeer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client, err := discovery.NewClient(discoveryURL, identity)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().(*net.TCPAddr).AddrPort()
	if _, err := client.Register(context.Background(), endpoint, vpnIP); err != nil {
		t.Fatalf("register: %v", err)
	}

	peer := &testPeer{
		identity: identity,
		vpnIP:    vpnIP,
		device:   newFakeDevice(),
		done:     make(chan error, 1),
	}
	manager := session.NewSessionManager(time.Hour, time.Hour, time.Hour, identity)
	t.Cleanup(manager.Shutdown)
	peer.node, err = New(Config{
		Sessions:          manager,
		Peers:             client,
		Listener:          listener,
		Device:            peer.device,
		PollInterval:      50 * time.Millisecond,
		KeepaliveInterval: 50 * time.Millisecond,
		MinBackoff:        20 * time.Millisecond,
		MaxBackoff:        100 * time.Millisecond,
		Logf:              t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	peer.cancel = cancel
	go func() { peer.done <- peer.node.Run(ctx) }()
	t.Cleanup(func() { _ = peer.stop() })
	return peer
}

// stop cancels the node and returns Run's result. It is safe to call repeatedly.
func (p *testPeer) stop() error {
	p.stopOnce.Do(func() {
		p.cancel()
		select {
		case p.err = <-p.done:
		case <-time.After(5 * time.Second):
			p.err = errors.New("Run did not return after cancel")
		}
	})
	return p.err
}

// ipv4Packet builds a minimal IPv4 header followed by payload. The checksum is
// not filled in; the mesh only routes on addresses.
func ipv4Packet(src, dst netip.Addr, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17 // UDP
	s, d := src.As4(), dst.As4()
	copy(packet[12:16], s[:])
	copy(packet[16:20], d[:])
	copy(packet[20:], payload)
	return packet
}

// sendUntilDelivered injects packet at from until it arrives at to. Packets
// injected before the session is up are dropped, so the first tries may fail.
func sendUntilDelivered(t *testing.T, from, to *testPeer, packet []byte) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		from.device.inject <- packet
		select {
		case got := <-to.device.delivered:
			if !bytes.Equal(got, packet) {
				t.Fatalf("delivered packet differs:\n got %x\nwant %x", got, packet)
			}
			return
		case <-time.After(100 * time.Millisecond):
		case <-deadline:
			t.Fatal("packet was never delivered")
		}
	}
}

func TestTwoPeersExchangePacketsThroughDiscovery(t *testing.T) {
	ca := testpki.NewCA(t)
	url := startDiscovery(t, ca)
	alice := startPeer(t, ca, url, "10.77.0.2")
	bob := startPeer(t, ca, url, "10.77.0.3")

	sendUntilDelivered(t, alice, bob, ipv4Packet(alice.vpnIP, bob.vpnIP, []byte("ping")))
	sendUntilDelivered(t, bob, alice, ipv4Packet(bob.vpnIP, alice.vpnIP, []byte("pong")))

	// Exactly one session per side, whichever peer dialed.
	if n := alice.node.cfg.Sessions.Count(); n != 1 {
		t.Fatalf("alice has %d sessions, want 1", n)
	}
	if n := bob.node.cfg.Sessions.Count(); n != 1 {
		t.Fatalf("bob has %d sessions, want 1", n)
	}
}

func TestSpoofedSourceIsDropped(t *testing.T) {
	ca := testpki.NewCA(t)
	url := startDiscovery(t, ca)
	alice := startPeer(t, ca, url, "10.77.0.2")
	bob := startPeer(t, ca, url, "10.77.0.3")

	// Wait for the tunnel to work, then send a packet claiming another source.
	sendUntilDelivered(t, alice, bob, ipv4Packet(alice.vpnIP, bob.vpnIP, []byte("ping")))
	alice.device.inject <- ipv4Packet(netip.MustParseAddr("10.77.0.99"), bob.vpnIP, []byte("spoofed"))
	alice.device.inject <- ipv4Packet(alice.vpnIP, bob.vpnIP, []byte("genuine"))

	select {
	case got := <-bob.device.delivered:
		if !bytes.HasSuffix(got, []byte("genuine")) {
			t.Fatalf("expected only the genuine packet, got %q", got[20:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("genuine packet was not delivered")
	}
}

func TestPeerReconnectsAfterRestart(t *testing.T) {
	ca := testpki.NewCA(t)
	url := startDiscovery(t, ca)
	alice := startPeer(t, ca, url, "10.77.0.2")
	bob := startPeer(t, ca, url, "10.77.0.3")
	sendUntilDelivered(t, alice, bob, ipv4Packet(alice.vpnIP, bob.vpnIP, []byte("before")))

	// Restart bob with the same identity on a new port.
	bob.stop()
	restarted := runPeer(t, url, bob.identity, bob.vpnIP)
	sendUntilDelivered(t, alice, restarted, ipv4Packet(alice.vpnIP, restarted.vpnIP, []byte("after")))
	sendUntilDelivered(t, restarted, alice, ipv4Packet(restarted.vpnIP, alice.vpnIP, []byte("after")))
}

func TestRunStopsCleanlyOnCancel(t *testing.T) {
	ca := testpki.NewCA(t)
	url := startDiscovery(t, ca)
	alice := startPeer(t, ca, url, "10.77.0.2")

	if err := alice.stop(); err != nil {
		t.Fatalf("Run returned %v after cancel", err)
	}
}

// staticPeers is a PeerSource with a fixed peer list.
type staticPeers []discovery.PeerRecord

func (p staticPeers) ListPeers(context.Context) ([]discovery.PeerRecord, error) { return p, nil }

// silentListener accepts connections and never responds, so handshakes with it
// hang. A value is sent on the returned channel when the dialer closes a connection.
func silentListener(t *testing.T) (net.Listener, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	closed := make(chan struct{}, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				conn.Close()
				closed <- struct{}{}
			}()
		}
	}()
	return listener, closed
}

func TestRunAbortsInFlightHandshakesOnCancel(t *testing.T) {
	identity := testpki.NewIdentity(t, testpki.NewCA(t))
	silent, silentClosed := silentListener(t)

	// A peer with the highest possible ID, so this node is the one that dials it.
	var highest uuid.UUID
	for i := range highest {
		highest[i] = 0xff
	}
	peers := staticPeers{{
		ID:      highest,
		Address: silent.Addr().(*net.TCPAddr).AddrPort(),
		VPNIP:   netip.MustParseAddr("10.77.0.9"),
	}}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewSessionManager(time.Hour, time.Hour, time.Hour, identity)
	t.Cleanup(manager.Shutdown)
	node, err := New(Config{Sessions: manager, Peers: peers, Listener: listener, Device: newFakeDevice(), Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- node.Run(ctx) }()

	// An inbound connection that never sends a hello.
	inbound, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()

	time.Sleep(200 * time.Millisecond) // let the outbound dial and inbound handshake start
	cancel()

	// Both handshakes would otherwise wait for the 10s handshake timeout.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return promptly with handshakes in flight")
	}
	// Run must not return while a handshake is still in progress: both stuck
	// connections have to be closed already.
	select {
	case <-silentClosed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("outbound handshake was still running after Run returned")
	}
	_ = inbound.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := inbound.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("inbound handshake was still running after Run returned (read: %v)", err)
	}
	if n := manager.Count(); n != 0 {
		t.Fatalf("%d sessions left after Run returned", n)
	}
}
