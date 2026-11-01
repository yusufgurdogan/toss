//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package rendezvous

import "syscall"

func ttlOpt(v6 bool) (level, opt int) {
	if v6 {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

func setTTL(rc syscall.RawConn, v6 bool, ttl int) error {
	level, opt := ttlOpt(v6)
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), level, opt, ttl) }); err != nil {
		return err
	}
	return serr
}

func getTTL(rc syscall.RawConn, v6 bool) int {
	level, opt := ttlOpt(v6)
	ttl := 64
	rc.Control(func(fd uintptr) {
		if v, err := syscall.GetsockoptInt(int(fd), level, opt); err == nil && v > 0 {
			ttl = v
		}
	})
	return ttl
}
