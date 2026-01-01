//go:build windows

package server

import "syscall"

func setSocketOptions(network, address string, c syscall.RawConn) error {
	return nil
}
