package network

import (
	"encoding/binary"
	"fmt"
	"net"
)

// SendWithLen sends data over a net.Conn with a big-endian length prefix.
func SendWithLen(conn net.Conn, data []byte) error {
	len := len(data)
	if len < 0 || len > 65535 {
		return fmt.Errorf("length must be between 0 and 65535, got %d", len)
	}

	// Create a buffer to hold the length prefix and data
	buf := make([]byte, 2+len)
	binary.BigEndian.PutUint16(buf[:2], uint16(len))
	copy(buf[2:], data)

	// Send the buffer over the connection
	_, err := conn.Write(buf)
	return err
}

// RecvWithLen receives data from a net.Conn with a big-endian length prefix.
func RecvWithLen(conn net.Conn) ([]byte, error) {
	// Read the length prefix (2 bytes)
	lenBuf := make([]byte, 2)
	_, err := conn.Read(lenBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}

	// Decode the length
	length := binary.BigEndian.Uint16(lenBuf)

	// Read the data based on the length
	dataBuf := make([]byte, length)
	_, err = conn.Read(dataBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return dataBuf, nil
}
