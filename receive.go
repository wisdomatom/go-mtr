package go_mtr

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"time"
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
	err = setSockOptRcvTimeout(fd, time.Second)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	rc := &rcvIpv4{
		fd:     fd,
		ctx:    ctx,
		cancel: cancel,
	}

	return rc, err
}

func (r *rcvIpv4) Receive() chan []byte {
	ch := make(chan []byte, 10000)
	ticker := time.NewTicker(time.Second)
	go func() {
		for {
			select {
			case <-r.ctx.Done():
				unix.Close(r.fd)
				// close ch when ctx done
				close(ch)
				return
			default:
			}
			bts := make([]byte, 512)
			_, _, err := unix.Recvfrom(r.fd, bts, 0)
			if err != nil {
				continue
			}
			ticker.Reset(time.Millisecond * 300)
			select {
			case ch <- bts:
			case <-ticker.C:
				fmt.Printf("receive ch full (%v)\n", time.Now())
			}
		}
	}()
	return ch
}

func (r *rcvIpv4) Close() {
	r.cancel()
}
