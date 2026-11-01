package connect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yusufgurdogan/toss/internal/code"
	"github.com/yusufgurdogan/toss/internal/dht"
	"github.com/yusufgurdogan/toss/internal/lan"
	"github.com/yusufgurdogan/toss/internal/qconn"
	"github.com/yusufgurdogan/toss/internal/rendezvous"
	"github.com/yusufgurdogan/toss/internal/secure"
)

func init() { dht.CacheDir = "" }

func mustCode(t *testing.T, s string) code.Code {
	t.Helper()
	c, err := code.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type served struct {
	err  error
	data string
}

// serve starts a sender for codeStr on a loopback listener and returns its
// address and a channel with the outcome.
func serve(t *testing.T, codeStr string) (string, chan served) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := secure.NewServer(mustCode(t, codeStr).Password())
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan served, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tc, err := Serve(ctx, ln, nil, srv, nil)
		if err != nil {
			out <- served{err: err}
			return
		}
		defer tc.Close()
		b, _ := io.ReadAll(tc)
		out <- served{data: string(b)}
	}()
	return ln.Addr().String(), out
}

const testCode = "1234-acid-acorn-acre"

func TestDirectAddress(t *testing.T) {
	addr, out := serve(t, testCode)
	// Junk connections first: they must not disturb the real receiver.
	for range 3 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
			c.Close()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tc, err := Dial(ctx, mustCode(t, testCode+"@"+addr), DialOptions{NoLAN: true, NoDHT: true})
	if err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte("payload"))
	tc.Close()
	if r := <-out; r.err != nil || r.data != "payload" {
		t.Fatalf("sender got %+v", r)
	}
}

func TestServeReturnsWhileOtherHandshakesPending(t *testing.T) {
	// A connection that never speaks (e.g. the same receiver reaching us
	// over a second path) must not keep Serve from returning.
	addr, out := serve(t, testCode)
	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tc, err := Dial(ctx, mustCode(t, testCode+"@"+addr), DialOptions{NoLAN: true, NoDHT: true})
	if err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte("x"))
	tc.Close()
	select {
	case r := <-out:
		if r.err != nil || r.data != "x" {
			t.Fatalf("sender got %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return while another handshake was pending")
	}
}

func TestStallingPeerDoesNotBlockSearch(t *testing.T) {
	// A fake "sender" that is found first, accepts and then says nothing
	// must not stop the receiver from reaching the real one, which here
	// only comes up later at the address in the code.
	stall, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stall.Close()
	var stalled atomic.Int32
	go func() {
		for {
			c, err := stall.Accept()
			if err != nil {
				return
			}
			stalled.Add(1)
			defer c.Close()
		}
	}()
	pc, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	discPort := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	r, err := lan.Listen(mustCode(t, testCode).MeetingID(), stall.Addr().(*net.TCPAddr).Port, lan.ListenOptions{Port: discPort, LoopbackOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	sent := make(chan error, 1)
	time.AfterFunc(500*time.Millisecond, func() {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			sent <- err
			return
		}
		srv, _ := secure.NewServer(mustCode(t, testCode).Password())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tc, err := Serve(ctx, ln, nil, srv, nil)
		if err == nil {
			tc.Close()
		}
		sent <- err
	})

	old := clientHandshakeTimeout
	clientHandshakeTimeout = 300 * time.Millisecond
	defer func() { clientHandshakeTimeout = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tc, err := Dial(ctx, mustCode(t, testCode+"@"+addr), DialOptions{
		NoDHT:      true,
		LANPort:    discPort,
		LANTargets: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(discPort))},
	})
	if err != nil {
		t.Fatal(err)
	}
	tc.Close()
	if err := <-sent; err != nil {
		t.Fatalf("sender: %v", err)
	}
	if stalled.Load() == 0 {
		t.Fatal("the stalling peer was never tried; the test proves nothing")
	}
}

func TestWrongCodeStopsBothSides(t *testing.T) {
	addr, out := serve(t, testCode)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Dial(ctx, mustCode(t, "1234-acid-acorn-acid@"+addr), DialOptions{NoLAN: true, NoDHT: true})
	var spe *secure.SentProofError
	if !errors.Is(err, secure.ErrWrongCode) || !errors.As(err, &spe) {
		t.Fatalf("receiver error %v", err)
	}
	if r := <-out; !errors.Is(r.err, secure.ErrWrongCode) {
		t.Fatalf("sender error %v", r.err)
	}
}

func TestLANDiscovery(t *testing.T) {
	addr, out := serve(t, testCode)
	ap := netip.MustParseAddrPort(addr)
	pc, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	discPort := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	r, err := lan.Listen(mustCode(t, testCode).MeetingID(), int(ap.Port()), lan.ListenOptions{Port: discPort, LoopbackOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tc, err := Dial(ctx, mustCode(t, testCode), DialOptions{
		NoDHT:      true,
		LANPort:    discPort,
		LANTargets: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(discPort))},
	})
	if err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte("via lan"))
	tc.Close()
	if r := <-out; r.err != nil || r.data != "via lan" {
		t.Fatalf("sender got %+v", r)
	}
}

func TestNotFound(t *testing.T) {
	// Grab a port with nothing listening.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, err := Dial(ctx, mustCode(t, testCode+"@"+addr), DialOptions{NoLAN: true, NoDHT: true})
	var nf *NotFoundError
	if !errors.As(err, &nf) || nf.Addr != addr || nf.LastErr == nil {
		t.Fatalf("error %v", err)
	}

	// Cancellation (Ctrl-C) is reported as such, not as "not found".
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := Dial(ctx, mustCode(t, testCode+"@"+addr), DialOptions{NoLAN: true, NoDHT: true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error after cancel %v", err)
	}
}

func TestSenderWaitsForLateReceiver(t *testing.T) {
	// The receiver starts first and retries until the sender is up.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tc, err := Dial(ctx, mustCode(t, testCode+"@"+addr), DialOptions{NoLAN: true, NoDHT: true})
		if err == nil {
			tc.Close()
		}
		done <- err
	}()
	time.Sleep(1500 * time.Millisecond)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip("port reused:", err)
	}
	srv, _ := secure.NewServer(mustCode(t, testCode).Password())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tc, err := Serve(ctx, ln, nil, srv, nil)
	if err != nil {
		t.Fatal(err)
	}
	tc.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestInternetPath(t *testing.T) {
	// Sender and receiver meet through a (fake, loopback) DHT and connect
	// over QUIC with hole-punching probes; no TCP, no LAN discovery.
	var nodes []*dht.FakeNode
	for range 8 {
		n, err := dht.NewFakeNode("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		n.Know(nodes...)
	}
	ropts := rendezvous.Options{Bind4: "127.0.0.1:0", NoIPv6: true, AllowPrivate: true,
		Bootstrap: []string{nodes[0].Addr().String()}, Poll: 200 * time.Millisecond}

	c := mustCode(t, testCode)
	srv, _ := secure.NewServer(c.Password())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rv, err := rendezvous.StartSender(ctx, c.MeetingID(), srv.TLSConfig(), qconn.Config(), ropts)
	if err != nil {
		t.Fatal(err)
	}
	defer rv.Close()
	out := make(chan served, 1)
	go func() {
		conn, err := Serve(ctx, nil, rv, srv, nil)
		if err != nil {
			out <- served{err: err}
			return
		}
		b, _ := io.ReadAll(conn)
		conn.Close()
		out <- served{data: string(b)}
	}()

	conn, err := Dial(ctx, c, DialOptions{NoLAN: true, Rendezvous: ropts})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(*closeHook); !ok {
		t.Fatalf("got %T, want a QUIC connection", conn)
	}
	conn.Write([]byte("hello over the internet path"))
	conn.Close()
	if r := <-out; r.err != nil || r.data != "hello over the internet path" {
		t.Fatalf("sender got %+v", r)
	}

	// A wrong code over this path burns the code just the same.
	srv2, _ := secure.NewServer(c.Password())
	rv2, err := rendezvous.StartSender(ctx, "5555-acid", srv2.TLSConfig(), qconn.Config(), ropts)
	if err != nil {
		t.Fatal(err)
	}
	defer rv2.Close()
	go Serve(ctx, nil, rv2, srv2, nil)
	_, err = Dial(ctx, mustCode(t, "5555-acid-acorn-acid"), DialOptions{NoLAN: true, Rendezvous: ropts})
	if !errors.Is(err, secure.ErrWrongCode) {
		t.Fatalf("wrong code over QUIC: %v", err)
	}
}
