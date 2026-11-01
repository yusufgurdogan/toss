//go:build !linux && !darwin && !freebsd && !windows

package xfer

import (
	"errors"
	"os"
)

func freeSpace(*os.Root) (int64, error) { return 0, errors.ErrUnsupported }
