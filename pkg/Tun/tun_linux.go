//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	tunSetIff = 0x400454ca // TUNSETIFF
	iffTun    = 0x0001
	iffNoPI   = 0x1000
)

// ifreq mirrors struct ifreq for TUNSETIFF: a name followed by flags, padded to 40 bytes.
type ifreq struct {
	name  [syscall.IFNAMSIZ]byte
	flags uint16
	_     [22]byte
}

type linuxDevice struct {
	file *os.File
	name string
	mtu  int
}

// Open creates the TUN interface name, assigns prefix (for example
// 10.77.0.2/24), sets the MTU, and brings it up. It needs CAP_NET_ADMIN and
// the ip command. The interface is removed when the device is closed.
func Open(name string, prefix netip.Prefix, mtu int) (Device, error) {
	if len(name) >= syscall.IFNAMSIZ {
		return nil, fmt.Errorf("interface name %q is too long", name)
	}
	if !prefix.Addr().Is4() {
		return nil, errors.New("only IPv4 overlay addresses are supported")
	}

	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var req ifreq
	copy(req.name[:], name)
	req.flags = iffTun | iffNoPI
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&req))); errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %s: %w", name, errno)
	}

	// Attach the interface before handing the descriptor to the runtime poller;
	// a non-blocking fd passed to os.NewFile is polled, so Close interrupts Read.
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("set non-blocking: %w", err)
	}

	dev := &linuxDevice{
		file: os.NewFile(uintptr(fd), "/dev/net/tun"),
		name: cString(req.name[:]),
		mtu:  mtu,
	}
	if err := dev.configure(prefix); err != nil {
		dev.file.Close()
		return nil, err
	}
	return dev, nil
}

func (d *linuxDevice) configure(prefix netip.Prefix) error {
	commands := [][]string{
		{"addr", "add", prefix.String(), "dev", d.name},
		{"link", "set", "dev", d.name, "mtu", strconv.Itoa(d.mtu), "up"},
	}
	for _, args := range commands {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %v: %w: %s", args, err, output)
		}
	}
	return nil
}

func (d *linuxDevice) Read(p []byte) (int, error)  { return d.file.Read(p) }
func (d *linuxDevice) Write(p []byte) (int, error) { return d.file.Write(p) }
func (d *linuxDevice) Close() error                { return d.file.Close() }
func (d *linuxDevice) Name() string                { return d.name }
func (d *linuxDevice) MTU() int                    { return d.mtu }

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
