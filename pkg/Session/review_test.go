package session

import (
	"crypto/rand"
	"net"
	"testing"
	"time"
	"uuid"

	aes "github.com/JacobSartin/SMESH-VPN/pkg/AES"
	network "github.com/JacobSartin/SMESH-VPN/pkg/Network"
)

// Tests added during code review. A failing test here means the weakness it
// describes is present.

// The data channel has no replay protection and both directions share one key
// with no direction binding. An on-path attacker can replay any frame, and can
// reflect a peer's own frames back to it.
func TestDataChannelRejectsReplayAndReflection(t *testing.T) {
	key := make([]byte, aes.KeySize256)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipherA, err := aes.NewAES256(key)
	if err != nil {
		t.Fatal(err)
	}
	cipherB, err := aes.NewAES256(key)
	if err != nil {
		t.Fatal(err)
	}

	connA, connB := net.Pipe()
	t.Cleanup(func() { connA.Close(); connB.Close() })

	a := &Session{connection: connA, cipher: cipherA, status: StatusEstablished, sessionID: uuid.NewV7()}
	b := &Session{connection: connB, cipher: cipherB, status: StatusEstablished, sessionID: uuid.NewV7()}

	sendErr := make(chan error, 1)
	go func() { sendErr <- a.Send([]byte("ping")) }()
	frame, err := network.RecvWithLen(connB)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sendErr; err != nil {
		t.Fatal(err)
	}

	if _, err := b.Receive(frame); err != nil {
		t.Fatalf("first delivery should succeed: %v", err)
	}
	if _, err := b.Receive(frame); err == nil {
		t.Error("replayed frame was accepted a second time")
	}
	if _, err := a.Receive(frame); err == nil {
		t.Error("sender accepted its own frame reflected back (no direction binding)")
	}
}

// Idle cleanup closes sessions directly instead of going through RemoveSession,
// so consumers never receive a Disconnected event for them.
func TestIdleCleanupEmitsDisconnectedEvent(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Nanosecond, time.Hour, nil)
	defer manager.Shutdown()

	events := make(chan SessionEvent, 4)
	manager.SetEventChannel(events)

	sessionID := addManagedTestSession(t, manager, time.Now().Add(-time.Hour))
	manager.CleanupIdleSessions()

	select {
	case event := <-events:
		if event.Type != SessionEventDisconnected || event.SessionID != sessionID {
			t.Fatalf("unexpected event %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("idle cleanup removed the session without emitting a Disconnected event")
	}
}

// The peer ID in the (unauthenticated) hello is chosen by the remote side. Two
// connections claiming the same ID collide in sessionsByPeerID, and removing
// the older session deletes the lookup entry for the newer one.
func TestRemovingOldSessionKeepsLookupForNewerSessionWithSamePeerID(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	defer manager.Shutdown()

	peerID := uuid.NewV7()
	first := acceptUnauthenticatedSession(t, manager, peerID)
	second := acceptUnauthenticatedSession(t, manager, peerID)

	if manager.Count() != 2 {
		t.Fatalf("expected both sessions to be tracked, got %d", manager.Count())
	}

	manager.RemoveSession(first.SessionID())

	got, ok := manager.GetSessionByPeerID(peerID)
	if !ok || got.SessionID() != second.SessionID() {
		t.Fatalf("after removing the old session, peer lookup should return the newer session %s; got ok=%v", second.SessionID(), ok)
	}
}

// A peer that connects and never sends a hello pins a goroutine and a socket
// forever, because the handshake has no read deadline.
func TestHandshakeHasDeadline(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	defer manager.Shutdown()

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close() })

	errCh := make(chan error, 1)
	go func() {
		_, err := manager.CreateSessionFromConnection(serverConn)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected the silent handshake to fail")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handshake with a silent peer did not time out")
	}
}

// acceptUnauthenticatedSession runs the server side of the unauthenticated
// handshake through the manager over an in-memory pipe, with the client side
// claiming peerID, and returns the server-side session.
func acceptUnauthenticatedSession(t *testing.T, manager *SessionManager, peerID uuid.UUID) *Session {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close() })

	type result struct {
		session *Session
		err     error
	}
	done := make(chan result, 1)
	go func() {
		s, err := manager.CreateSessionFromConnection(serverConn)
		done <- result{s, err}
	}()

	client := &Session{connection: clientConn, status: StatusInitializing, sessionID: uuid.NewV7()}
	if err := client.establishUnauthenticatedKeyExchange(&ClientIdentity{ID: peerID}); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("server handshake: %v", r.err)
		}
		return r.session
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not complete")
		return nil
	}
}
