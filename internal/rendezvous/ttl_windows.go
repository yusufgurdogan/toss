//go:build windows

package rendezvous

import "syscall"

func setTTL(rc syscall.RawConn, v6 bool, ttl int) error {
	level, opt := syscall.IPPROTO_IP, syscall.IP_TTL
	if v6 {
		level, opt = syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(syscall.Handle(fd), level, opt, ttl) }); err != nil {
		return err
	}
	return serr
}

func getTTL(syscall.RawConn, bool) int { return 128 } // the Windows default
