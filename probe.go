package go_mtr

import (
	"golang.org/x/sys/unix"
	"time"
)

type Detector interface {
	Probe(req SendProbe) error
	Close()
}

type detectMock struct{}

func (*detectMock) Probe(probe SendProbe) error {
	return nil
}

func (*detectMock) Close() {}

type probeIpv4 struct {
	detectMock
}

type probeIpv6 struct {
	detectMock
}

func newProbeIpv6() Detector {
	return &probeIpv6{}
}

type SendProbe struct {
	Trace
	WriteTimeout time.Duration
	Msg          []byte
}

func newProbeIpv4() Detector {
	p4 := &probeIpv4{}
	return p4
}

func (p *probeIpv4) Close() {

}

func (p *probeIpv4) Probe(req SendProbe) error {
	return p.probe(req)
}

func (p *probeIpv4) probe(req SendProbe) error {
	var fd int
	var err error
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		return err
	}
	err = unix.Bind(fd, req.SrcSockAddr)
	if err != nil {
		return err
	}
	err = unix.Sendto(fd, req.Msg, 0, req.DstSockAddr)
	return err
}
