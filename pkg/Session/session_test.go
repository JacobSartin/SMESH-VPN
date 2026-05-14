package session

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustNewV7(t *testing.T) uuid.UUID {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("failed to generate UUIDv7: %v", err)
	}

	return id
}

func TestUnauthenticatedSessionKeyExchangeAndMessaging(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverResult := make(chan struct {
		session *Session
		err     error
	}, 1)

	go func() {
		serverSession, err := NewSessionFromConn(serverConn, nil)
		serverResult <- struct {
			session *Session
			err     error
		}{session: serverSession, err: err}
	}()

	clientSession := &Session{
		connection:   clientConn,
		peer:         PeerInfo{ID: uuid.NullUUID{UUID: mustNewV7(t), Valid: true}, Address: serverConn.LocalAddr()},
		status:       StatusInitializing,
		established:  time.Now(),
		lastActivity: time.Now(),
		sessionID:    mustNewV7(t),
	}

	if err := clientSession.EstablishKeyExchange(nil); err != nil {
		t.Fatalf("client key exchange failed: %v", err)
	}
	defer clientSession.Close()

	var serverSession *Session
	select {
	case result := <-serverResult:
		if result.err != nil {
			t.Fatalf("server key exchange failed: %v", result.err)
		}
		serverSession = result.session
	case <-time.After(time.Second):
		t.Fatal("server key exchange timed out")
	}
	defer serverSession.Close()

	if clientSession.Status() != StatusEstablished {
		t.Fatalf("expected client session established, got %v", clientSession.Status())
	}
	if serverSession.Status() != StatusEstablished {
		t.Fatalf("expected server session established, got %v", serverSession.Status())
	}
	if clientSession.SessionID().Version() != 7 {
		t.Fatalf("expected client session ID to be UUIDv7, got v%d", clientSession.SessionID().Version())
	}
	if serverSession.SessionID().Version() != 7 {
		t.Fatalf("expected server session ID to be UUIDv7, got v%d", serverSession.SessionID().Version())
	}
	if !serverSession.PeerInfo().ID.Valid {
		t.Fatal("expected unauthenticated handshake to assign a peer ID")
	}
	if serverSession.PeerInfo().ID.UUID.Version() != 7 {
		t.Fatalf("expected peer ID to be UUIDv7, got v%d", serverSession.PeerInfo().ID.UUID.Version())
	}

	message := []byte("hello from unauthenticated session")
	readResult := make(chan struct {
		data []byte
		err  error
	}, 1)

	go func() {
		data, err := serverSession.Read()
		readResult <- struct {
			data []byte
			err  error
		}{data: data, err: err}
	}()

	if err := clientSession.Send(message); err != nil {
		t.Fatalf("client send failed: %v", err)
	}

	select {
	case result := <-readResult:
		if result.err != nil {
			t.Fatalf("server read failed: %v", result.err)
		}
		if !bytes.Equal(result.data, message) {
			t.Fatalf("expected %q, got %q", message, result.data)
		}
	case <-time.After(time.Second):
		t.Fatal("server read timed out")
	}
}
