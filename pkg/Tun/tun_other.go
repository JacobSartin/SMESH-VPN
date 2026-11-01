//go:build !linux

package tun

import (
	"errors"
	"net/netip"
)

// Open is not supported on this platform.
func Open(name string, prefix netip.Prefix, mtu int) (Device, error) {
	return nil, errors.New("TUN devices are only supported on Linux")
}
