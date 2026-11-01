//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package xfer

import "syscall"

// openFlags make the sender refuse a symlink swapped in after the files
// were listed, and not block on a FIFO swapped in the same way.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
