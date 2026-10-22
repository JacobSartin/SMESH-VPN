// Package tun provides the virtual network interface that carries overlay
// traffic. Only Linux is supported.
package tun

import "io"

// DefaultMTU leaves room for TCP/IP headers and session framing on a 1500-byte path.
const DefaultMTU = 1400

// Device is a layer-3 virtual interface. Each Read returns one IP packet and
// each Write injects one IP packet.
type Device interface {
	io.ReadWriteCloser
	// Name is the OS interface name.
	Name() string
	// MTU is the interface MTU; packets read are never larger.
	MTU() int
}
