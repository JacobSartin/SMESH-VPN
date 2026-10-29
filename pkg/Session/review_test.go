package session

import (
	"crypto/rand"
	"net"
	"sync"
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
//
// The test does not pin a duplicate policy. Rejecting the second connection,
// or closing the first and replacing it, both satisfy the invariant checked
// here: whenever the manager tracks any session for a peer, the peer lookup
// must resolve to a session that is still tracked and still open.
func TestPeerLookupStaysConsistentWhenPeerIDsCollide(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	defer manager.Shutdown()

	peerID := uuid.NewV7()
	first, err := acceptUnauthenticatedSession(t, manager, peerID)
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	// A reject-new policy is allowed to fail here.
	_, _ = acceptUnauthenticatedSession(t, manager, peerID)

	assertPeerLookupConsistent(t, manager, peerID)

	// Removing the first session (a no-op if a replace policy already did so)
	// must not strand whichever session the lookup points at.
	manager.RemoveSession(first.SessionID())
	assertPeerLookupConsistent(t, manager, peerID)
}

func assertPeerLookupConsistent(t *testing.T, manager *SessionManager, peerID uuid.UUID) {
	t.Helper()

	if manager.Count() == 0 {
		return
	}
	got, ok := manager.GetSessionByPeerID(peerID)
	if !ok {
		t.Fatalf("manager tracks %d session(s) but has no lookup entry for peer %s", manager.Count(), peerID)
	}
	if _, tracked := manager.GetSession(got.SessionID()); !tracked {
		t.Fatalf("peer lookup returned session %s, which the manager no longer tracks", got.SessionID())
	}
	if got.Status() == StatusClosed {
		t.Fatalf("peer lookup returned closed session %s", got.SessionID())
	}
}

// A peer that connects and never sends a hello pins a goroutine and a socket
// forever, because the handshake never arms a read deadline. The test checks
// for the deadline itself rather than waiting for a timeout, so any finite
// value the implementation chooses will pass.
func TestHandshakeArmsReadDeadline(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	defer manager.Shutdown()

	serverConn, clientConn := net.Pipe()
	observed := &deadlineObservingConn{Conn: serverConn, firstRead: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		_, _ = manager.CreateSessionFromConnection(observed)
		close(done)
	}()

	select {
	case <-observed.firstRead:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake never attempted to read from the connection")
	}

	// Unblock the handshake, whatever it is doing.
	_ = clientConn.Close()
	<-done

	if !observed.deadlineArmedBeforeFirstRead() {
		t.Fatal("handshake started reading from the peer without arming a read deadline")
	}
}

// deadlineObservingConn records whether a read deadline was armed before the
// first Read, and signals when that first Read happens.
type deadlineObservingConn struct {
	net.Conn
	mu        sync.Mutex
	armed     bool
	readSeen  bool
	armedAtRd bool
	firstRead chan struct{}
}

func (c *deadlineObservingConn) SetDeadline(t time.Time) error {
	c.noteDeadline(t)
	return c.Conn.SetDeadline(t)
}

func (c *deadlineObservingConn) SetReadDeadline(t time.Time) error {
	c.noteDeadline(t)
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineObservingConn) noteDeadline(t time.Time) {
	c.mu.Lock()
	c.armed = !t.IsZero()
	c.mu.Unlock()
}

func (c *deadlineObservingConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if !c.readSeen {
		c.readSeen = true
		c.armedAtRd = c.armed
		close(c.firstRead)
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

func (c *deadlineObservingConn) deadlineArmedBeforeFirstRead() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readSeen && c.armedAtRd
}

// acceptUnauthenticatedSession runs the server side of the unauthenticated
// handshake through the manager over an in-memory pipe, with the client side
// claiming peerID, and returns the server-side session or the error the
// manager reported.
func acceptUnauthenticatedSession(t *testing.T, manager *SessionManager, peerID uuid.UUID) (*Session, error) {
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
	clientErr := client.establishUnauthenticatedKeyExchange(&ClientIdentity{ID: peerID})

	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		if clientErr != nil {
			return nil, clientErr
		}
		return r.session, nil
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not complete")
		return nil, nil
	}
}
