package network

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SendWithLen sends data over a net.Conn with a big-endian length prefix.
func SendWithLen(conn net.Conn, data []byte) error {
	if len(data) > 65535 {
		return fmt.Errorf("length must be at most 65535, got %d", len(data))
	}

	// Create a buffer to hold the length prefix and data
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(data)))
	copy(buf[2:], data)

	written := 0
	for written < len(buf) {
		n, err := conn.Write(buf[written:])
		if err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}
		written += n
	}

	return nil
}

// RecvWithLen receives data from a net.Conn with a big-endian length prefix.
func RecvWithLen(conn net.Conn) ([]byte, error) {
	// Read the length prefix (2 bytes)
	lenBuf := make([]byte, 2)
	_, err := io.ReadFull(conn, lenBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}

	// Decode the length
	length := binary.BigEndian.Uint16(lenBuf)

	// Read the data based on the length
	dataBuf := make([]byte, length)
	_, err = io.ReadFull(conn, dataBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return dataBuf, nil
}
