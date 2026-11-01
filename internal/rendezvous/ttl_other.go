//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly || windows)

package rendezvous

import (
	"errors"
	"syscall"
)

func setTTL(syscall.RawConn, bool, int) error { return errors.ErrUnsupported }
func getTTL(syscall.RawConn, bool) int        { return 64 }
