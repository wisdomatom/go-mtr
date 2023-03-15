package go_mtr

import (
	"context"
	"golang.org/x/sys/unix"
)

type Receiver interface {
	Receive() chan []byte
	Close()
}

type rcvIpv4 struct {
	fd     int
	ctx    context.Context
	cancel func()
}

func newRcvIpv4() (Receiver, error) {
	var err error
	var fd int
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
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
