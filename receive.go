package go_mtr

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"time"
)

type Receiver interface {
	Receive() (chan []byte, error)
	Close()
}

type rcvMock struct{}

func (r *rcvMock) Receive() (chan []byte, error) {
	return nil, nil
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
	Config
	fd     int
	ctx    context.Context
	cancel func()
}

func newRcvIpv4(conf Config) (Receiver, error) {
	rc := &rcvIpv4{
		//fd:     fd,
		//ctx:    ctx,
		//cancel: cancel,
		Config: conf,
	}
	return rc, nil
}

func (r *rcvIpv4) initSocket() error {
	var err error
	var fd int
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	err = setSockOptReceiveErr(fd)
	if err != nil {
		return err
	}
	err = setSockOptRcvTimeout(fd, time.Second)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.ctx = ctx
	r.cancel = cancel
	r.fd = fd
	return nil
}

func (r *rcvIpv4) Receive() (chan []byte, error) {
	var err error
	err = r.initSocket()
	if err != nil {
		return nil, err
	}
	ch := make(chan []byte, 10000)
	go func() {
		for {
			select {
			case <-r.ctx.Done():
				err = unix.Close(r.fd)
				if err != nil {
					Error(r.ErrCh, err)
				}
				// close ch when ctx done
				close(ch)
				return
			default:
			}
			bts := make([]byte, 512)
			_, _, err = unix.Recvfrom(r.fd, bts, 0)
			if err != nil {
				continue
			}
			if len(bts) > 20 && bts[20] == 8 {
				// icmp echo should be ignored
				continue
			}
			select {
			case ch <- bts:
			default:
				Error(r.ErrCh, fmt.Errorf("error: receive ch full (%v)\n", time.Now()))
			}
		}
	}()
	return ch, nil
}

func (r *rcvIpv4) Close() {
	r.cancel()
}
