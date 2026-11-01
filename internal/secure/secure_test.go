package secure

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yusufgurdogan/toss/internal/cpace"
)

const pw = "7392-river-moon-sun"

// tcpPair returns two ends of a real loopback TCP connection.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		ch <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-ch
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

type result struct {
	conn *tls.Conn
	err  error
}

// run performs one handshake between a fresh connection pair.
func run(t *testing.T, s *Server, clientPW string) (client, server result) {
	t.Helper()
	cc, sc := tcpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan result)
	go func() {
		c, err := s.Handshake(ctx, sc)
		done <- result{c, err}
	}()
	c, err := Client(ctx, cc, clientPW)
	return result{c, err}, <-done
}

func TestHandshakeSuccess(t *testing.T) {
	s, err := NewServer(pw)
	if err != nil {
		t.Fatal(err)
	}
	c, sv := run(t, s, pw)
	if c.err != nil || sv.err != nil {
		t.Fatalf("client err %v, server err %v", c.err, sv.err)
	}
	// The channel works both ways.
	go func() {
		sv.conn.Write([]byte("hello receiver"))
	}()
	buf := make([]byte, 14)
	if _, err := io.ReadFull(c.conn, buf); err != nil || string(buf) != "hello receiver" {
		t.Fatalf("read %q, %v", buf, err)
	}
	go func() {
		c.conn.Write([]byte("hi sender"))
	}()
	buf = make([]byte, 9)
	if _, err := io.ReadFull(sv.conn, buf); err != nil || string(buf) != "hi sender" {
		t.Fatalf("read %q, %v", buf, err)
	}

	// The code is single use: a second receiver, even with the right
	// code, is refused.
	c2, s2 := run(t, s, pw)
	if !errors.Is(c2.err, ErrRefused) || !errors.Is(s2.err, ErrRefused) {
		t.Fatalf("second use: client err %v, server err %v", c2.err, s2.err)
	}
	var spe *SentProofError
	if !errors.As(c2.err, &spe) {
		t.Fatalf("refusal should be a SentProofError, got %T", c2.err)
	}
}

func TestWrongCodeBurns(t *testing.T) {
	s, err := NewServer(pw)
	if err != nil {
		t.Fatal(err)
	}
	c, sv := run(t, s, "7392-river-moon-sum")
	if !errors.Is(c.err, ErrWrongCode) || !errors.Is(sv.err, ErrWrongCode) {
		t.Fatalf("client err %v, server err %v", c.err, sv.err)
	}
	var spe *SentProofError
	if !errors.As(c.err, &spe) {
		t.Fatalf("wrong code should be a SentProofError, got %T", c.err)
	}
	if !s.Burned() {
		t.Fatal("server not burned after wrong code")
	}
	// Even the right code no longer works.
	c, sv = run(t, s, pw)
	if !errors.Is(c.err, ErrRefused) || !errors.Is(sv.err, ErrRefused) {
		t.Fatalf("after burn: client err %v, server err %v", c.err, sv.err)
	}
}

func TestConcurrentGuessesGetOneChance(t *testing.T) {
	s, err := NewServer(pw)
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wrong, refused := 0, 0
	for range n {
		wg.Go(func() {
			_, sv := run(t, s, "0000-acid-acorn-acre")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(sv.err, ErrWrongCode):
				wrong++
			case errors.Is(sv.err, ErrRefused):
				refused++
			default:
				t.Errorf("unexpected server error %v", sv.err)
			}
		})
	}
	wg.Wait()
	if wrong != 1 || refused != n-1 {
		t.Fatalf("wrong=%d refused=%d, want exactly one evaluated guess", wrong, refused)
	}
}

func TestVersionMismatch(t *testing.T) {
	s, err := NewServer(pw)
	if err != nil {
		t.Fatal(err)
	}
	cc, sc := tcpPair(t)
	done := make(chan error)
	go func() {
		_, err := s.Handshake(context.Background(), sc)
		done <- err
	}()
	cc.Write([]byte("TOSS\x07"))
	got, err := readPreamble(cc)
	if err != nil || got != ProtocolVersion {
		t.Fatalf("server preamble %d, %v", got, err)
	}
	var ve *VersionError
	if err := <-done; !errors.As(err, &ve) || ve.Peer != 7 {
		t.Fatalf("server error %v", err)
	}
	if s.Burned() {
		t.Fatal("a version mismatch must not burn the code")
	}

	// And from the client's point of view.
	cc, sc = tcpPair(t)
	go func() {
		readPreamble(sc)
		sc.Write([]byte("TOSS\x00"))
	}()
	if _, err := Client(context.Background(), cc, pw); !errors.As(err, &ve) || ve.Peer != 0 {
		t.Fatalf("client error %v", err)
	}
}

func TestNotToss(t *testing.T) {
	s, err := NewServer(pw)
	if err != nil {
		t.Fatal(err)
	}
	for _, junk := range []string{"GET / HTTP/1.1\r\n\r\n", "", "TOS"} {
		cc, sc := tcpPair(t)
		done := make(chan error)
		go func() {
			_, err := s.Handshake(context.Background(), sc)
			done <- err
		}()
		cc.Write([]byte(junk))
		cc.(*net.TCPConn).CloseWrite()
		if err := <-done; !errors.Is(err, ErrNotToss) {
			t.Errorf("junk %q: server error %v", junk, err)
		}
	}
	if s.Burned() {
		t.Fatal("junk connections must not burn the code")
	}
}

func TestAbortBeforeProofDoesNotBurn(t *testing.T) {
	// A peer that runs the PAKE but disconnects before sending its proof
	// learns nothing, so it must not burn the code (else anyone could
	// cheaply deny service... they can anyway, but not silently).
	s, err := NewServer(pw)
	if err != nil {
		t.Fatal(err)
	}
	cc, sc := tcpPair(t)
	done := make(chan error)
	go func() {
		_, err := s.Handshake(context.Background(), sc)
		done <- err
	}()
	cc.Write(preamble())
	readPreamble(cc)
	tc := tls.Client(cc, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tc.Write(make([]byte, msgALen)) // not a valid element: the server rejects it
	if err := <-done; err == nil || errors.Is(err, ErrWrongCode) {
		t.Fatalf("server error %v", err)
	}
	if s.Burned() {
		t.Fatal("burned without a proof")
	}
	c, sv := run(t, s, pw)
	if c.err != nil || sv.err != nil {
		t.Fatalf("real receiver after aborted attempt: client %v, server %v", c.err, sv.err)
	}
}

// TestMITM runs an attacker that terminates TLS on both sides and relays the
// PAKE messages verbatim. Without the code it must fail, and the sender
// counts it as one wrong guess.
func TestMITM(t *testing.T) {
	s, err := NewServer(pw)
	if err != nil {
		t.Fatal(err)
	}
	mitmServer, err := NewServer("irrelevant")
	if err != nil {
		t.Fatal(err)
	}
	victimC, mitmFromVictim := tcpPair(t)
	mitmToSender, senderSide := tcpPair(t)

	senderDone := make(chan error, 1)
	go func() {
		_, err := s.Handshake(context.Background(), senderSide)
		senderDone <- err
	}()
	clientDone := make(chan error, 1)
	go func() {
		_, err := Client(context.Background(), victimC, pw)
		clientDone <- err
	}()

	// Attacker: TLS server towards the victim, TLS client towards the sender.
	readPreamble(mitmFromVictim)
	mitmFromVictim.Write(preamble())
	down := tls.Server(mitmFromVictim, mitmServer.tlsConf)
	mitmToSender.Write(preamble())
	readPreamble(mitmToSender)
	up := tls.Client(mitmToSender, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13})
	errs := make(chan error, 2)
	go func() { errs <- down.Handshake() }()
	go func() { errs <- up.Handshake() }()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	relay := func(dst io.Writer, src io.Reader, n int) {
		buf := make([]byte, n)
		if _, err := io.ReadFull(src, buf); err != nil {
			return
		}
		dst.Write(buf)
	}
	relay(up, down, msgALen)  // msgA
	relay(down, up, msgBLen)  // msgB
	relay(up, down, macLen)   // receiver proof
	relay(down, up, 1+macLen) // status (+ sender proof)
	down.Close()

	if err := <-senderDone; !errors.Is(err, ErrWrongCode) {
		t.Fatalf("sender error %v, want ErrWrongCode", err)
	}
	if err := <-clientDone; err == nil {
		t.Fatal("victim completed a handshake through a MITM")
	}
}

func TestContextCancel(t *testing.T) {
	s, err := NewServer(pw)
	if err != nil {
		t.Fatal(err)
	}
	_, sc := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		_, err := s.Handshake(ctx, sc)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("handshake succeeded with a silent peer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake ignored context cancellation")
	}
}

// breakableConn fails every write once broken is set.
type breakableConn struct {
	net.Conn
	broken *atomic.Bool
}

func (c breakableConn) Write(b []byte) (int, error) {
	if c.broken.Load() {
		return 0, errors.New("connection broke")
	}
	return c.Conn.Write(b)
}

func TestLostAfterProof(t *testing.T) {
	// The right receiver proves the code, then the sender can't answer:
	// the sender must report that the code is spent rather than wait.
	s, err := NewServer(pw)
	if err != nil {
		t.Fatal(err)
	}
	cc, sc := tcpPair(t)
	var broken atomic.Bool
	done := make(chan error, 1)
	go func() {
		_, err := s.Handshake(context.Background(), breakableConn{sc, &broken})
		done <- err
	}()
	// Run the client by hand up to its proof.
	cc.Write(preamble())
	readPreamble(cc)
	tc := tls.Client(cc, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	ekm, _ := exporter(tc)
	msgA, state, _ := cpaceStart(pw, ekm)
	tc.Write(msgA)
	msgB := make([]byte, msgBLen)
	io.ReadFull(tc, msgB)
	key, _ := state.Finish(msgB)
	recvKey, _, _ := confirmKeys(key)
	broken.Store(true)
	tc.Write(confirmMAC(recvKey, idReceiver, msgA, msgB))
	if err := <-done; !errors.Is(err, ErrLostAfterProof) {
		t.Fatalf("server error %v, want ErrLostAfterProof", err)
	}
	// And nobody else gets in with that code.
	c, sv := run(t, s, pw)
	if !errors.Is(c.err, ErrRefused) || !errors.Is(sv.err, ErrRefused) {
		t.Fatalf("after loss: client %v, server %v", c.err, sv.err)
	}
}

func cpaceStart(password string, ekm []byte) ([]byte, interface{ Finish([]byte) ([]byte, error) }, error) {
	msgA, st, err := cpace.Start(password, contextInfo(ekm))
	return msgA, st, err
}
