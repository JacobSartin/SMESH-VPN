package session

import (
	"fmt"
	"net"
	"sync"
	"time"
	"uuid"
)

// SessionEvent represents different types of session events
type SessionEvent struct {
	Type      SessionEventType
	SessionID uuid.UUID
	Session   *Session
	Error     error
}

// SessionEventType represents the type of session event
type SessionEventType int

const (
	SessionEventConnected SessionEventType = iota
	SessionEventDisconnected
	SessionEventError
)

// SessionEventHandler is a function that handles session events
type SessionEventHandler func(event SessionEvent)

// SessionManager handles multiple active sessions, keeping at most one per peer.
type SessionManager struct {
	// mu protects access to the sessions map
	mu sync.RWMutex
	// sessions is a map of session ID to Session instance
	sessions map[uuid.UUID]*Session
	// sessionsByPeerID allows looking up sessions by peer ID
	sessionsByPeerID map[uuid.UUID]*Session
	// cleanupInterval determines how often idle session cleanup runs
	cleanupInterval time.Duration
	// maxIdleTime is how long a session may go without receiving a frame before it is closed
	maxIdleTime time.Duration
	// maxKeyAge is how long a session key may be used before the session is closed so it is re-established
	maxKeyAge time.Duration
	// stopCleanup is a channel to signal the cleanup goroutine to stop
	stopCleanup  chan struct{}
	shutdownOnce sync.Once
	// clientIdentity is the identity of this client, used across all sessions
	clientIdentity *ClientIdentity
	// eventHandlers is a slice of functions to call when session events occur
	eventHandlers []SessionEventHandler
	// eventChannel is a channel for session events (optional, can be nil)
	eventChannel chan SessionEvent
}

// NewSessionManager creates a new session manager
func NewSessionManager(cleanupInterval, maxIdleTime, maxKeyAge time.Duration, identity *ClientIdentity) *SessionManager {
	sm := &SessionManager{
		sessions:         make(map[uuid.UUID]*Session),
		sessionsByPeerID: make(map[uuid.UUID]*Session),
		cleanupInterval:  cleanupInterval,
		maxIdleTime:      maxIdleTime,
		maxKeyAge:        maxKeyAge,
		stopCleanup:      make(chan struct{}),
		clientIdentity:   identity,
	}

	go sm.cleanupRoutine()

	return sm
}

// Identity returns the identity used for new sessions.
func (sm *SessionManager) Identity() *ClientIdentity {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.clientIdentity
}

// GetSession retrieves a session by its ID
func (sm *SessionManager) GetSession(sessionID uuid.UUID) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	return session, exists
}

// GetSessionByPeerID retrieves a session by the peer's ID
func (sm *SessionManager) GetSessionByPeerID(peerID uuid.UUID) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessionsByPeerID[peerID]
	return session, exists
}

// Sessions returns a snapshot of the active sessions.
func (sm *SessionManager) Sessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// RemoveSession closes a session and removes it from the manager. Removing a
// session that is no longer managed is a no-op.
func (sm *SessionManager) RemoveSession(sessionID uuid.UUID) {
	sm.mu.Lock()
	session, exists := sm.sessions[sessionID]
	if exists {
		sm.unlinkLocked(session)
	}
	sm.mu.Unlock()

	if exists {
		sm.closeAndNotify(session)
	}
}

// CloseAll closes all active sessions
func (sm *SessionManager) CloseAll() {
	sm.mu.Lock()
	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	sm.sessions = make(map[uuid.UUID]*Session)
	sm.sessionsByPeerID = make(map[uuid.UUID]*Session)
	sm.mu.Unlock()

	for _, session := range sessions {
		_ = session.Close()
	}
}

// Count returns the number of active sessions
func (sm *SessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return len(sm.sessions)
}

// ListSessionIDs returns a list of all session IDs
func (sm *SessionManager) ListSessionIDs() []uuid.UUID {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	ids := make([]uuid.UUID, 0, len(sm.sessions))
	for id := range sm.sessions {
		ids = append(ids, id)
	}
	return ids
}

// Shutdown stops the cleanup routine and closes all sessions. It is safe to call more than once.
func (sm *SessionManager) Shutdown() {
	sm.shutdownOnce.Do(func() {
		close(sm.stopCleanup)
		sm.CloseAll()
	})
}

// cleanupRoutine periodically checks for and removes idle sessions
func (sm *SessionManager) cleanupRoutine() {
	ticker := time.NewTicker(sm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.CleanupIdleSessions()
			sm.expireAgedSessions()
		case <-sm.stopCleanup:
			return
		}
	}
}

// CleanupIdleSessions removes sessions that have not received a frame within maxIdleTime.
func (sm *SessionManager) CleanupIdleSessions() {
	sm.removeWhere(func(s *Session) bool { return s.IdleTime() > sm.maxIdleTime })
}

// expireAgedSessions closes sessions whose key is older than maxKeyAge. The
// owner reconnects, which runs a fresh key exchange.
func (sm *SessionManager) expireAgedSessions() {
	sm.removeWhere(func(s *Session) bool { return s.KeyAge() > sm.maxKeyAge })
}

func (sm *SessionManager) removeWhere(match func(*Session) bool) {
	sm.mu.Lock()
	removed := make([]*Session, 0)
	for _, session := range sm.sessions {
		if match(session) {
			sm.unlinkLocked(session)
			removed = append(removed, session)
		}
	}
	sm.mu.Unlock()

	for _, session := range removed {
		sm.closeAndNotify(session)
	}
}

// CreateSession dials a peer and adds the resulting session to the manager.
func (sm *SessionManager) CreateSession(peerInfo PeerInfo) (*Session, error) {
	session, err := NewSession(peerInfo, sm.Identity())
	if err != nil {
		return nil, err
	}
	sm.addSession(session)
	return session, nil
}

// CreateSessionFromConnection completes the handshake on an accepted connection
// and adds the resulting session to the manager.
func (sm *SessionManager) CreateSessionFromConnection(conn net.Conn) (*Session, error) {
	session, err := NewSessionFromConn(conn, sm.Identity())
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		sm.notifyEvent(SessionEvent{
			Type:  SessionEventError,
			Error: err,
		})
		return nil, err
	}

	sm.addSession(session)
	return session, nil
}

// addSession registers session. If the peer already has a session, the older
// one is closed: a peer that restarts or reconnects replaces its stale session.
func (sm *SessionManager) addSession(session *Session) {
	sm.mu.Lock()
	replaced, hadSession := sm.sessionsByPeerID[session.PeerID()]
	if hadSession {
		sm.unlinkLocked(replaced)
	}
	sm.sessions[session.SessionID()] = session
	sm.sessionsByPeerID[session.PeerID()] = session
	sm.mu.Unlock()

	if hadSession {
		sm.closeAndNotify(replaced)
	}
	sm.notifyEvent(SessionEvent{
		Type:      SessionEventConnected,
		SessionID: session.SessionID(),
		Session:   session,
	})
}

// unlinkLocked removes session from both maps. sm.mu must be held.
func (sm *SessionManager) unlinkLocked(session *Session) {
	delete(sm.sessions, session.sessionID)
	if current, ok := sm.sessionsByPeerID[session.peer.ID]; ok && current == session {
		delete(sm.sessionsByPeerID, session.peer.ID)
	}
}

func (sm *SessionManager) closeAndNotify(session *Session) {
	_ = session.Close()
	sm.notifyEvent(SessionEvent{
		Type:      SessionEventDisconnected,
		SessionID: session.SessionID(),
		Session:   session,
	})
}

// SetEventChannel sets a channel to receive session events
func (sm *SessionManager) SetEventChannel(ch chan SessionEvent) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.eventChannel = ch
}

// AddEventHandler adds a callback function to handle session events
func (sm *SessionManager) AddEventHandler(handler SessionEventHandler) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.eventHandlers = append(sm.eventHandlers, handler)
}

// notifyEvent sends an event to all registered handlers and the event channel.
// Handlers run on their own goroutines; events are dropped if the channel is full.
func (sm *SessionManager) notifyEvent(event SessionEvent) {
	sm.mu.RLock()
	handlers := make([]SessionEventHandler, len(sm.eventHandlers))
	copy(handlers, sm.eventHandlers)
	eventChannel := sm.eventChannel
	sm.mu.RUnlock()

	for _, handler := range handlers {
		go func(h SessionEventHandler) {
			defer func() { _ = recover() }()
			h(event)
		}(handler)
	}

	if eventChannel != nil {
		select {
		case eventChannel <- event:
		default:
		}
	}
}

// ListenForNewConnections accepts connections and creates sessions until the
// listener is closed. It blocks, so it is typically run in a goroutine.
func (sm *SessionManager) ListenForNewConnections(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			sm.notifyEvent(SessionEvent{
				Type:  SessionEventError,
				Error: fmt.Errorf("failed to accept connection: %w", err),
			})
			return err
		}

		go func(conn net.Conn) {
			_, _ = sm.CreateSessionFromConnection(conn)
		}(conn)
	}
}
