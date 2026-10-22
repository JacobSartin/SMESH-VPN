package session_test

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
	"uuid"

	"github.com/JacobSartin/SMESH-VPN/internal/testpki"
	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

// listen starts a manager accepting sessions on a loopback port.
func listen(t *testing.T, identity *session.ClientIdentity) (*session.SessionManager, net.Addr, chan session.SessionEvent) {
	t.Helper()
	manager := session.NewSessionManager(time.Hour, time.Hour, time.Hour, identity)
	t.Cleanup(manager.Shutdown)
	events := make(chan session.SessionEvent, 16)
	manager.SetEventChannel(events)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go manager.ListenForNewConnections(listener)
	return manager, listener.Addr(), events
}

func waitEvent(t *testing.T, events chan session.SessionEvent, want session.SessionEventType) session.SessionEvent {
	t.Helper()
	for {
		select {
		case event := <-events:
			if event.Type == want {
				return event
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for event type %d", want)
		}
	}
}

func TestAuthenticatedSessionBindsCertificateIdentities(t *testing.T) {
	ca := testpki.NewCA(t)
	alice := testpki.NewIdentity(t, ca)
	bob := testpki.NewIdentity(t, ca)

	bobManager, bobAddr, bobEvents := listen(t, bob)
	aliceManager := session.NewSessionManager(time.Hour, time.Hour, time.Hour, alice)
	t.Cleanup(aliceManager.Shutdown)

	aliceSide, err := aliceManager.CreateSession(session.PeerInfo{ID: bob.ID, Address: bobAddr})
	if err != nil {
		t.Fatalf("dial bob: %v", err)
	}
	if got := aliceSide.PeerID(); got != bob.ID {
		t.Fatalf("alice sees peer %s, want bob %s", got, bob.ID)
	}

	bobSide := waitEvent(t, bobEvents, session.SessionEventConnected).Session
	if got := bobSide.PeerID(); got != alice.ID {
		t.Fatalf("bob sees peer %s, want alice %s", got, alice.ID)
	}
	if _, ok := bobManager.GetSessionByPeerID(alice.ID); !ok {
		t.Fatal("bob's manager has no session for alice")
	}

	// Keepalives are consumed by Read; only data frames are returned.
	if err := aliceSide.SendKeepalive(); err != nil {
		t.Fatal(err)
	}
	message := []byte("hello bob")
	if err := aliceSide.Send(message); err != nil {
		t.Fatal(err)
	}
	got, err := bobSide.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, message) {
		t.Fatalf("bob read %q, want %q", got, message)
	}
}

func TestAuthenticatedSessionRejectsUnexpectedPeer(t *testing.T) {
	ca := testpki.NewCA(t)
	alice := testpki.NewIdentity(t, ca)
	bob := testpki.NewIdentity(t, ca)
	_, bobAddr, _ := listen(t, bob)

	_, err := session.NewSession(session.PeerInfo{ID: uuid.NewV7(), Address: bobAddr}, alice)
	if !errors.Is(err, session.ErrUnexpectedPeer) {
		t.Fatalf("expected ErrUnexpectedPeer, got %v", err)
	}
}

func TestAuthenticatedSessionRejectsPeerFromOtherCA(t *testing.T) {
	alice := testpki.NewIdentity(t, testpki.NewCA(t))
	mallory := testpki.NewIdentity(t, testpki.NewCA(t))
	_, malloryAddr, _ := listen(t, mallory)

	if _, err := session.NewSession(session.PeerInfo{ID: mallory.ID, Address: malloryAddr}, alice); err == nil {
		t.Fatal("expected a peer from another CA to be rejected")
	}
}

func TestHandshakeModeMismatchIsReported(t *testing.T) {
	ca := testpki.NewCA(t)
	alice := testpki.NewIdentity(t, ca)
	_, addr, events := listen(t, nil) // unauthenticated listener

	_, _ = session.NewSession(session.PeerInfo{ID: uuid.NewV7(), Address: addr}, alice)

	event := waitEvent(t, events, session.SessionEventError)
	if !errors.Is(event.Error, session.ErrHandshakeMismatch) {
		t.Fatalf("expected ErrHandshakeMismatch, got %v", event.Error)
	}
}

func TestSilentPeerTimesOutDuringHandshake(t *testing.T) {
	defer session.SetHandshakeTimeout(200 * time.Millisecond)()
	identity := testpki.NewIdentity(t, testpki.NewCA(t))

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		_, err := session.NewSessionFromConn(server, identity)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected handshake with a silent peer to fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake with a silent peer did not time out")
	}
}
