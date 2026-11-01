package session

import (
	"net"
	"testing"
	"time"
	"uuid"
)

func TestRemoveSessionDoesNotDeadlockWhenEventsEnabled(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	defer manager.Shutdown()

	events := make(chan SessionEvent, 1)
	manager.SetEventChannel(events)

	sessionID := addManagedTestSession(t, manager, time.Now())

	done := make(chan struct{})
	go func() {
		manager.RemoveSession(sessionID)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RemoveSession deadlocked while notifying event listeners")
	}

	select {
	case event := <-events:
		if event.Type != SessionEventDisconnected {
			t.Fatalf("expected disconnected event, got %v", event.Type)
		}
		if event.SessionID != sessionID {
			t.Fatalf("expected session ID %s, got %s", sessionID, event.SessionID)
		}
	case <-time.After(time.Second):
		t.Fatal("expected disconnected event")
	}

	if manager.Count() != 0 {
		t.Fatalf("expected all sessions removed, got %d", manager.Count())
	}
}

func TestCreateSessionFromConnectionErrorDoesNotDeadlock(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	defer manager.Shutdown()

	events := make(chan SessionEvent, 1)
	manager.SetEventChannel(events)

	errCh := make(chan error, 1)
	go func() {
		_, err := manager.CreateSessionFromConnection(nil)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	case <-time.After(time.Second):
		t.Fatal("CreateSessionFromConnection deadlocked while notifying error listeners")
	}

	select {
	case event := <-events:
		if event.Type != SessionEventError {
			t.Fatalf("expected error event, got %v", event.Type)
		}
		if event.Error == nil {
			t.Fatal("expected error event to include error")
		}
	case <-time.After(time.Second):
		t.Fatal("expected error event")
	}
}

func TestCleanupIdleSessionsClosesSessionsOutsideManagerLock(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Nanosecond, time.Hour, nil)
	defer manager.Shutdown()

	sessionID := addManagedTestSession(t, manager, time.Now().Add(-time.Hour))

	manager.CleanupIdleSessions()

	if manager.Count() != 0 {
		t.Fatalf("expected idle session to be removed, got %d sessions", manager.Count())
	}

	if _, exists := manager.GetSession(sessionID); exists {
		t.Fatal("idle session still exists after cleanup")
	}
}

func addManagedTestSession(t *testing.T, manager *SessionManager, lastActivity time.Time) uuid.UUID {
	t.Helper()

	conn, peerConn := net.Pipe()
	t.Cleanup(func() {
		_ = peerConn.Close()
	})

	sessionID := uuid.NewV7()
	peerID := uuid.NewV7()
	testSession := &Session{
		connection:   conn,
		peer:         PeerInfo{ID: peerID, Address: peerConn.LocalAddr()},
		status:       StatusEstablished,
		established:  time.Now(),
		lastActivity: lastActivity,
		sessionID:    sessionID,
	}

	manager.mu.Lock()
	manager.sessions[sessionID] = testSession
	manager.sessionsByPeerID[peerID] = testSession
	manager.mu.Unlock()

	return sessionID
}

func TestCleanupIdleSessionsEmitsDisconnected(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Minute, time.Hour, nil)
	defer manager.Shutdown()
	events := make(chan SessionEvent, 4)
	manager.SetEventChannel(events)

	idleID := addManagedTestSession(t, manager, time.Now().Add(-time.Hour))
	activeID := addManagedTestSession(t, manager, time.Now())

	manager.CleanupIdleSessions()

	if _, exists := manager.GetSession(activeID); !exists {
		t.Fatal("active session was removed")
	}
	select {
	case event := <-events:
		if event.Type != SessionEventDisconnected || event.SessionID != idleID {
			t.Fatalf("expected disconnect for idle session %s, got type %d for %s", idleID, event.Type, event.SessionID)
		}
	case <-time.After(time.Second):
		t.Fatal("idle cleanup did not emit a disconnect event")
	}
}

func TestAddSessionReplacesExistingSessionForPeer(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	defer manager.Shutdown()

	oldID := addManagedTestSession(t, manager, time.Now())
	old, _ := manager.GetSession(oldID)

	conn, peerConn := net.Pipe()
	t.Cleanup(func() { _ = peerConn.Close() })
	replacement := &Session{
		connection:   conn,
		peer:         PeerInfo{ID: old.PeerID(), Address: peerConn.LocalAddr()},
		status:       StatusEstablished,
		established:  time.Now(),
		lastActivity: time.Now(),
		sessionID:    uuid.NewV7(),
	}
	manager.addSession(replacement)

	if manager.Count() != 1 {
		t.Fatalf("expected one session after replacement, got %d", manager.Count())
	}
	if current, _ := manager.GetSessionByPeerID(old.PeerID()); current != replacement {
		t.Fatal("peer lookup does not return the replacement session")
	}
	if old.Status() != StatusClosed {
		t.Fatal("replaced session was not closed")
	}

	// A late RemoveSession for the replaced session must not touch the new one.
	manager.RemoveSession(oldID)
	if _, ok := manager.GetSessionByPeerID(old.PeerID()); !ok {
		t.Fatal("removing the replaced session dropped the replacement")
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	manager := NewSessionManager(time.Hour, time.Hour, time.Hour, nil)
	manager.Shutdown()
	manager.Shutdown()
}
