package mesh

import "net/netip"

// ipv4Addresses returns the source and destination of an IPv4 packet.
func ipv4Addresses(packet []byte) (src, dst netip.Addr, ok bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, false
	}
	src = netip.AddrFrom4([4]byte(packet[12:16]))
	dst = netip.AddrFrom4([4]byte(packet[16:20]))
	return src, dst, true
}
