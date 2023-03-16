package go_mtr

import (
	"context"
	"golang.org/x/sys/unix"
)

type Receiver interface {
	Receive() chan []byte
	Close()
}

type rcvMock struct{}

func (r *rcvMock) Receive() chan []byte {
	return nil
}

func (r *rcvMock) Close() {}

type rcvIpv6 struct {
	rcvMock
}

func newRcvIpv6() (Receiver, error) {
	return &rcvIpv6{}, nil
}

type rcvIpv4 struct {
	rcvMock
	fd     int
	ctx    context.Context
	cancel func()
}

func newRcvIpv4() (Receiver, error) {
	var err error
	var fd int
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {

		return nil, err
	}
	err = setSockOptReceiveErr(fd)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	rc := &rcvIpv4{
		fd:     fd,
		ctx:    ctx,
		cancel: cancel,
	}
	return rc, nil
}

func (r *rcvIpv4) Receive() chan []byte {
	ch := make(chan []byte, 1000)
	go func() {
		for {
			select {
			case <-r.ctx.Done():
				unix.Close(r.fd)
				return
			default:
			}
			bts := make([]byte, 512)
			_, _, err := unix.Recvfrom(r.fd, bts, 0)
			if err != nil {
				continue
			}
			ch <- bts
		}
	}()
	return ch
}

func (r *rcvIpv4) Close() {
	r.cancel()
}
