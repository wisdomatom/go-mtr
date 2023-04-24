package go_mtr

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func checksum(buf []byte) uint16 {
	sum := uint32(0)
	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	cSum := ^uint16(sum)
	/*
	 * From RFC 768:
	 * If the computed checksum is zero, it is transmitted as all ones (the
	 * equivalent in one's complement arithmetic). An all zero transmitted
	 * checksum value means that the transmitter generated no checksum (for
	 * debugging or for higher level protocols that don't care).
	 */
	if cSum == 0 {
		cSum = 0xffff
	}
	return cSum
}

func IsIpv4(ip string) bool {
	for i := 0; i < len(ip); i++ {
		switch ip[i] {
		case '.':
			return true
		case ':':
			return false
		}
	}
	return false
}

func GetTrace(t *Trace) (*Trace, error) {
	if t.Retry < 1 {
		t.Retry = 1
	}
	src := net.ParseIP(t.SrcAddr)
	if src == nil {
		return t, fmt.Errorf("invalid src addr (%v)", t.SrcAddr)
	}
	dst := net.ParseIP(t.DstAddr)
	if dst == nil {
		return t, fmt.Errorf("invalid dst addr (%v)", t.DstAddr)
	}
	if IsIpv4(t.SrcAddr) {
		var addr [4]byte
		copy(addr[:], src.To4())
		sock := unix.SockaddrInet4{
			Port: int(t.SrcPort),
			Addr: addr,
		}
		t.SrcSockAddr = &sock
	} else {
		var addr [16]byte
		copy(addr[:], src.To16())
		sock := unix.SockaddrInet6{
			Port:   int(t.SrcPort),
			ZoneId: 0,
			Addr:   addr,
		}
		t.SrcSockAddr = &sock
	}
	if IsIpv4(t.DstAddr) {
		var addr [4]byte
		copy(addr[:], dst.To4())
		sock := unix.SockaddrInet4{
			Port: int(t.DstPort),
			Addr: addr,
		}
		t.IsIpv4 = true
		t.DstSockAddr = &sock
	} else {
		var addr [16]byte
		copy(addr[:], dst.To16())
		sock := unix.SockaddrInet6{
			Port: int(t.DstPort),
			Addr: addr,
		}
		t.DstSockAddr = &sock
	}
	return t, nil
}
