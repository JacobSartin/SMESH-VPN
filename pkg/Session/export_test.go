package session

import "time"

// SetHandshakeTimeout overrides the handshake timeout and returns a restore func.
func SetHandshakeTimeout(d time.Duration) (restore func()) {
	previous := handshakeTimeout
	handshakeTimeout = d
	return func() { handshakeTimeout = previous }
}
