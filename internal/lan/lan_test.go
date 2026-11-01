package lan

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func loopbackTargets(port int) []netip.AddrPort {
	return []netip.AddrPort{
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)),
		netip.AddrPortFrom(netip.IPv6Loopback(), uint16(port)),
	}
}

func TestFindOnLoopback(t *testing.T) {
	port := freeUDPPort(t)
	r, err := Listen("1234-acid", 40001, ListenOptions{Port: port, LoopbackOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	found, err := Find(ctx, "1234-acid", FindOptions{Port: port, Interval: 100 * time.Millisecond, Targets: loopbackTargets(port)})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ap := <-found:
		if ap.Port() != 40001 || !ap.Addr().IsLoopback() {
			t.Fatalf("found %v", ap)
		}
	case <-ctx.Done():
		t.Fatal("sender not found")
	}
	// Repeated query rounds don't produce duplicates of the same address.
	seen := map[netip.AddrPort]int{}
	timeout := time.After(500 * time.Millisecond)
loop:
	for {
		select {
		case ap := <-found:
			seen[ap]++
		case <-timeout:
			break loop
		}
	}
	for ap, n := range seen {
		if n > 1 {
			t.Errorf("%v reported %d times", ap, n)
		}
	}
	cancel()
	for range found {
	}
}

func TestFindIgnoresOtherMeetings(t *testing.T) {
	port := freeUDPPort(t)
	r, err := Listen("1234-acid", 40001, ListenOptions{Port: port, LoopbackOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	found, err := Find(ctx, "1234-acorn", FindOptions{Port: port, Interval: 100 * time.Millisecond, Targets: loopbackTargets(port)})
	if err != nil {
		t.Fatal(err)
	}
	for ap := range found {
		t.Errorf("found %v for a different meeting ID", ap)
	}
}

func TestResponderIgnoresJunk(t *testing.T) {
	port := freeUDPPort(t)
	r, err := Listen("1234-acid", 40001, ListenOptions{Port: port, LoopbackOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	id := ID("1234-acid")
	for _, junk := range [][]byte{
		nil, []byte("toss1?"), append([]byte("toss1?"), id[:]...),
		append(append([]byte("toss1!"), id[:]...), make([]byte, 16)...),
		append(append([]byte("toss1?"), id[:]...), make([]byte, 17)...),
	} {
		c.WriteToUDP(junk, dst)
	}
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 100)
	if n, _, err := c.ReadFromUDP(buf); err == nil {
		t.Fatalf("responder answered junk: %q", buf[:n])
	}
}

func TestAutoTargets(t *testing.T) {
	ts := autoTargets(DefaultPort)
	want := map[string]bool{"239.255.116.115": false, "255.255.255.255": false, "127.0.0.1": false}
	for _, ap := range ts {
		if ap.Port() != DefaultPort {
			t.Errorf("target %v has the wrong port", ap)
		}
		if _, ok := want[ap.Addr().String()]; ok {
			want[ap.Addr().String()] = true
		}
	}
	for a, ok := range want {
		if !ok {
			t.Errorf("missing target %s", a)
		}
	}
}

func TestOnLink(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "::1", "fe80::1%eth0", "::ffff:127.0.0.1"} {
		if !onLink(netip.MustParseAddr(a)) {
			t.Errorf("%s should be on-link", a)
		}
	}
	// Documentation addresses are never configured on test machines.
	for _, a := range []string{"192.0.2.1", "2001:db8::1", "8.8.8.8"} {
		if onLink(netip.MustParseAddr(a)) {
			t.Errorf("%s should not be on-link", a)
		}
	}
}

func TestID(t *testing.T) {
	if ID("1234-acid") == ID("1234-acorn") || ID("1234-acid") != ID("1234-acid") {
		t.Fatal("ID is not a function of the meeting ID")
	}
}

func TestFindCapsCandidates(t *testing.T) {
	// A host answering every query with many different ports can't make
	// the receiver chase more than MaxCandidates addresses.
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	port := c.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 100)
		for {
			n, src, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n != queryLen {
				continue
			}
			for p := 1; p <= 3*MaxCandidates; p++ {
				r := append([]byte(replyMagic), buf[len(queryMagic):n]...)
				r = append(r, byte(p>>8), byte(p))
				c.WriteToUDPAddrPort(r, src)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	found, err := Find(ctx, "1234-acid", FindOptions{Port: port, Interval: 200 * time.Millisecond, Targets: loopbackTargets(port)[:1]})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range found {
		n++
	}
	if n != MaxCandidates {
		t.Fatalf("got %d candidates, want %d", n, MaxCandidates)
	}
}
