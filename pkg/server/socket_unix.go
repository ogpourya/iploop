//go:build !windows

package server

import "syscall"

func setSocketOptions(network, address string, c syscall.RawConn) error {
	var sysErr error
	err := c.Control(func(fd uintptr) {
		sysErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		if sysErr != nil {
			return
		}
		sysErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	})
	if err != nil {
		return err
	}
	return sysErr
}
