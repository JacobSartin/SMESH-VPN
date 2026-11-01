package session

import (
	"crypto/rand"
	"net"
	"testing"
	"time"
	"uuid"

	aes "github.com/JacobSartin/SMESH-VPN/pkg/AES"
)

// A peer that stops reading must not block a sender forever: the write times
// out, and the session is closed because the stream may hold a partial frame.
func TestSendToStalledPeerTimesOutAndClosesSession(t *testing.T) {
	defer SetWriteTimeout(100 * time.Millisecond)()

	key := make([]byte, aes.KeySize256)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := aes.NewAES256(key)
	if err != nil {
		t.Fatal(err)
	}
	conn, stalledPeer := net.Pipe() // writes block until the other end reads, which it never does
	defer stalledPeer.Close()
	s := &Session{connection: conn, cipher: cipher, status: StatusEstablished, sessionID: uuid.NewV7()}

	done := make(chan error, 1)
	go func() { done <- s.Send([]byte("packet")) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("send to a peer that never reads succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("send to a stalled peer blocked past the write timeout")
	}
	if s.Status() != StatusClosed {
		t.Fatalf("session status %v after a failed write, want closed", s.Status())
	}
	if err := s.SendKeepalive(); err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed after a failed write, got %v", err)
	}
}
