package session

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
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

// SessionManager handles multiple active sessions
type SessionManager struct {
	// mu protects access to the sessions map
	mu sync.RWMutex
	// sessions is a map of session ID to Session instance
	sessions map[string]*Session
	// sessionsByPeerID allows looking up sessions by peer ID
	sessionsByPeerID map[string]*Session
	// cleanupInterval determines how often idle session cleanup runs
	cleanupInterval time.Duration
	// maxIdleTime is the maximum time a session can be idle before cleanup
	maxIdleTime time.Duration
	// maxKeyAge is the maximum age of a session key before rekeying
	maxKeyAge time.Duration
	// stopCleanup is a channel to signal the cleanup goroutine to stop
	stopCleanup chan struct{}
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
		sessions:         make(map[string]*Session),
		sessionsByPeerID: make(map[string]*Session),
		cleanupInterval:  cleanupInterval,
		maxIdleTime:      maxIdleTime,
		maxKeyAge:        maxKeyAge,
		stopCleanup:      make(chan struct{}),
		clientIdentity:   identity, // Will be set with SetClientIdentity
	}

	// Start the cleanup goroutine
	go sm.cleanupRoutine()

	return sm
}

// GetSession retrieves a session by its ID
func (sm *SessionManager) GetSession(sessionID uuid.UUID) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID.String()]
	return session, exists
}

// GetSessionByPeerID retrieves a session by the peer's ID
func (sm *SessionManager) GetSessionByPeerID(peerID string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessionsByPeerID[peerID]
	return session, exists
}

// RemoveSession removes a session from the manager
func (sm *SessionManager) RemoveSession(sessionID uuid.UUID) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID.String()]; exists {
		// Close the session
		_ = session.Close()

		// Remove from both maps
		delete(sm.sessionsByPeerID, session.peer.ID.UUID.String())
		delete(sm.sessions, sessionID.String())

		// Notify about the disconnection
		sm.notifyEvent(SessionEvent{
			Type:      SessionEventDisconnected,
			SessionID: sessionID,
			Session:   session,
		})
	}
}

// CloseAll closes all active sessions
func (sm *SessionManager) CloseAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, session := range sm.sessions {
		_ = session.Close()
	}

	// Clear the maps
	sm.sessions = make(map[string]*Session)
	sm.sessionsByPeerID = make(map[string]*Session)
}

// Count returns the number of active sessions
func (sm *SessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return len(sm.sessions)
}

// ListSessionIDs returns a list of all session IDs
func (sm *SessionManager) ListSessionIDs() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	ids := make([]string, 0, len(sm.sessions))
	for id := range sm.sessions {
		ids = append(ids, id)
	}
	return ids
}

// Shutdown stops the cleanup routine and closes all sessions
func (sm *SessionManager) Shutdown() {
	// Signal the cleanup routine to stop
	close(sm.stopCleanup)

	// Close all sessions
	sm.CloseAll()
}

// cleanupRoutine periodically checks for and removes idle sessions
func (sm *SessionManager) cleanupRoutine() {
	ticker := time.NewTicker(sm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.CleanupIdleSessions()
			sm.rekeyAgingSessions()
		case <-sm.stopCleanup:
			return
		}
	}
}

// cleanupIdleSessions removes sessions that have been idle for too long
func (sm *SessionManager) CleanupIdleSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, session := range sm.sessions {
		if session.IdleTime() > sm.maxIdleTime {
			// Close the session
			_ = session.Close()

			// Remove from both maps
			delete(sm.sessionsByPeerID, session.peer.ID.UUID.String())
			delete(sm.sessions, id)
		}
	}
}

// rekeyAgingSessions performs key rotation for sessions with old keys
func (sm *SessionManager) rekeyAgingSessions() {
	sm.mu.RLock()
	sessionsToRekey := make([]string, 0)

	for id, session := range sm.sessions {
		// Just collect IDs that need rekeying to avoid deadlock
		if time.Since(session.established) > sm.maxKeyAge {
			sessionsToRekey = append(sessionsToRekey, id)
		}
	}
	sm.mu.RUnlock()

	// Now rekey each session that needs it
	for _, id := range sessionsToRekey {
		sm.mu.RLock()
		session, exists := sm.sessions[id]
		sm.mu.RUnlock()

		if exists {
			_ = session.RekeyIfNeeded(sm.maxKeyAge)
		}
	}
}

// CreateSession creates a new session with a peer using the client's identity
// This is the recommended way to create a session as it handles session setup internally
func (sm *SessionManager) CreateSession(peerInfo PeerInfo) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Create a new session with the identity already injected
	// This uses the specific constructor that properly sets up the session with identity
	session, err := NewSession(peerInfo, sm.clientIdentity)
	if err != nil {
		return nil, err
	}

	// Add the session to the manager
	sm.sessions[session.sessionID.String()] = session
	sm.sessionsByPeerID[session.peer.ID.UUID.String()] = session

	return session, nil
}

func (sm *SessionManager) CreateSessionFromConnection(conn net.Conn) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Create a new session with the identity already injected
	session, err := NewSessionFromConn(conn, sm.clientIdentity)
	if err != nil {
		// Notify about the error
		sm.notifyEvent(SessionEvent{
			Type:  SessionEventError,
			Error: err,
		})
		return nil, err
	}

	// Add the session to the manager
	sm.sessions[session.sessionID.String()] = session
	sm.sessionsByPeerID[session.peer.ID.UUID.String()] = session

	// Notify about the new connection
	sm.notifyEvent(SessionEvent{
		Type:      SessionEventConnected,
		SessionID: session.sessionID,
		Session:   session,
	})

	return session, nil
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

// notifyEvent sends an event to all registered handlers and the event channel
func (sm *SessionManager) notifyEvent(event SessionEvent) {
	sm.mu.RLock()
	handlers := make([]SessionEventHandler, len(sm.eventHandlers))
	copy(handlers, sm.eventHandlers)
	eventChannel := sm.eventChannel
	sm.mu.RUnlock()

	// Call all registered handlers
	for _, handler := range handlers {
		go func(h SessionEventHandler) {
			defer func() {
				if r := recover(); r != nil {
					// TODO: Add proper logging
					// fmt.Printf("Event handler panic: %v\n", r)
				}
			}()
			h(event)
		}(handler)
	}

	// Send to event channel if set
	if eventChannel != nil {
		select {
		case eventChannel <- event:
		default:
			// TODO: Add logging for dropped events
			// Consider implementing event queuing or larger buffer
		}
	}
}

// ListenForNewConnections starts listening for new connections and creates sessions
// This function blocks and should typically be run in a goroutine
func (sm *SessionManager) ListenForNewConnections(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Notify about the accept error
			sm.notifyEvent(SessionEvent{
				Type:  SessionEventError,
				Error: fmt.Errorf("failed to accept connection: %w", err),
			})
			return err // Accept failed, return error
		}

		// Create a new session from the accepted connection
		// This runs in the current goroutine - each connection is handled synchronously
		// If you want concurrent handling, you could wrap this in a goroutine
		_, err = sm.CreateSessionFromConnection(conn)
		if err != nil {
			// Error is already notified in CreateSessionFromConnection
			// Continue to accept new connections despite this error
			continue
		}
	}
}
