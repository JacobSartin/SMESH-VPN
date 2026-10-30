package session

import "time"

// SetHandshakeTimeout overrides the handshake timeout and returns a restore func.
func SetHandshakeTimeout(d time.Duration) (restore func()) {
	previous := handshakeTimeout
	handshakeTimeout = d
	return func() { handshakeTimeout = previous }
}

// SetWriteTimeout overrides the frame write timeout and returns a restore func.
func SetWriteTimeout(d time.Duration) (restore func()) {
	previous := writeTimeout
	writeTimeout = d
	return func() { writeTimeout = previous }
}
