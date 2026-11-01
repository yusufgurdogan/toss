//go:build linux || darwin || freebsd

package xfer

import (
	"os"
	"syscall"
)

// freeSpace returns the bytes available to unprivileged users at root.
func freeSpace(root *os.Root) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(root.Name(), &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
