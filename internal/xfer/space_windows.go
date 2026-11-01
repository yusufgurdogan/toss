//go:build windows

package xfer

import (
	"os"
	"syscall"
	"unsafe"
)

var getDiskFreeSpaceExW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

// freeSpace returns the bytes available to the current user at root.
func freeSpace(root *os.Root) (int64, error) {
	p, err := syscall.UTF16PtrFromString(root.Name())
	if err != nil {
		return 0, err
	}
	var avail uint64
	r, _, err := getDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&avail)), 0, 0)
	if r == 0 {
		return 0, err
	}
	return int64(avail), nil
}
