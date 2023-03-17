package go_mtr

import "golang.org/x/sys/unix"

func setSockOptReceiveErr(fd int) error {
	err := unix.SetsockoptInt(fd, 0, unix.IP_RECVERR, 1)
	return err
}
