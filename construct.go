package go_mtr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"

	"golang.org/x/sys/unix"
)

type Constructor interface {
	Packet(req ConstructPacket) ([]byte, error)
}

type constructMock struct{}

func (*constructMock) Packet(packet ConstructPacket) ([]byte, error) {
	return nil, nil
}

type constructIpv4 struct {
	constructMock
	Config
}

type constructIpv6 struct {
	constructMock
}

func newConstructIpv6(conf Config) Constructor {
	ct := &constructIpv6{}
	return ct
}

type ConstructPacket struct {
	Trace
	Id      uint16
	Seq     uint16
	SrcPort uint16
	DstPort uint16
}

type headerIpv4 struct {
	vhl      uint8
	tos      uint8
	length   uint16
	id       uint16
	off      uint16
	ttl      uint8
	proto    uint8
	checkSum uint16
	src      [4]byte
	dst      [4]byte
}

type headerIpv4UDP struct {
	srcPort  uint16
	dstPort  uint16
	length   uint16
	checkSum uint16
}

type headerPseudo struct {
	ipSrc   [4]byte
	ipDst   [4]byte
	zero    uint8
	ipProto uint8
	length  uint16
}

type headerICMPEcho struct {
	typ      uint8
	code     uint8
	checkSum uint16
	id       uint16
	seq      uint16
}

func (h *headerIpv4) checksum() {
	h.checkSum = 0
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, h)
	h.checkSum = checksum(b.Bytes())
}

func (h *headerICMPEcho) checksum() {
	h.checkSum = 0
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, h)
	//binary.Write(&b, binary.BigEndian, payload)
	h.checkSum = checksum(b.Bytes())
}

func (h *headerIpv4UDP) checksum(ip *headerIpv4, payload []byte) {
	h.checkSum = 0
	pse := headerPseudo{
		ipSrc:   ip.src,
		ipDst:   ip.dst,
		zero:    0,
		ipProto: ip.proto,
		length:  h.length,
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, &pse)
	binary.Write(&b, binary.BigEndian, h)
	binary.Write(&b, binary.BigEndian, &payload)
	h.checkSum = checksum(b.Bytes())
}

func newConstructIpv4(conf Config) Constructor {
	ct := &constructIpv4{Config: conf}
	return ct
}

func (c *constructIpv4) Packet(req ConstructPacket) ([]byte, error) {
	var err error
	var bts []byte
	if c.ICMP {
		bts, err = c.packetICMP(req)
	} else if c.UDP {
		bts, err = c.packetUDP(req)
	} else {
		return nil, fmt.Errorf("no define packet type")
	}
	if err != nil {
		return bts, err
	}
	if runtime.GOOS == "darwin" {
		bts[2], bts[3] = bts[3], bts[2]
	}
	return bts, nil
}

func (c *constructIpv4) packetICMP(req ConstructPacket) ([]byte, error) {
	var err error
	var hdIp4 *headerIpv4
	hdIp4, err = c.ipv4Header(req, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	hdICMP := &headerICMPEcho{
		typ:      8,
		code:     0,
		checkSum: 0,
		id:       req.Id,
		seq:      req.Seq,
	}
	hdICMP.checksum()

	icmpLen := uint16(8)
	totalLen := 20 + icmpLen
	hdIp4.length = totalLen
	hdIp4.checksum()

	var b bytes.Buffer
	err = binary.Write(&b, binary.BigEndian, hdIp4)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&b, binary.BigEndian, hdICMP)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (c *constructIpv4) packetUDP(req ConstructPacket) ([]byte, error) {
	var err error
	var hdIp4 *headerIpv4
	hdIp4, err = c.ipv4Header(req, unix.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	hdUDP := &headerIpv4UDP{
		srcPort: req.SrcPort,
		dstPort: req.DstPort,
	}
	payload := []byte("a")
	udpLen := uint16(8 + len(payload))
	totalLen := 20 + udpLen
	hdIp4.length = totalLen
	hdIp4.checksum()
	hdUDP.length = udpLen
	hdUDP.checksum(hdIp4, payload)

	var b bytes.Buffer
	err = binary.Write(&b, binary.BigEndian, hdIp4)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&b, binary.BigEndian, hdUDP)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&b, binary.BigEndian, &payload)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (c *constructIpv4) ipv4Header(req ConstructPacket, proto uint8) (*headerIpv4, error) {
	ipSrc := net.ParseIP(req.SrcAddr)
	if ipSrc == nil {
		return nil, fmt.Errorf("invalid source addr (%v)", req.SrcAddr)
	}
	ipDst := net.ParseIP(req.DstAddr)
	if ipDst == nil {
		return nil, fmt.Errorf("invalid dest addr (%v)", req.DstAddr)
	}
	ip4Src := ipSrc.To4()
	ip4Dst := ipDst.To4()
	hdIp4 := headerIpv4{
		vhl:      0x45,
		tos:      0,
		length:   0,
		id:       req.Id,
		off:      0,
		ttl:      req.MaxTTL,
		proto:    proto,
		checkSum: 0,
		src:      [4]byte{ip4Src[0], ip4Src[1], ip4Src[2], ip4Src[3]},
		dst:      [4]byte{ip4Dst[0], ip4Dst[1], ip4Dst[2], ip4Dst[3]},
	}

	return &hdIp4, nil
}

func (c *constructIpv4) icmp() {

}
