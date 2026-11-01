// Package connect establishes the secure connection between a toss sender
// and receiver: the sender accepts connections and runs handshakes until
// one succeeds, and the receiver finds the sender (on the LAN or at a given
// address), connects and runs the handshake exactly once.
package connect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/yusufgurdogan/toss/internal/code"
	"github.com/yusufgurdogan/toss/internal/lan"
	"github.com/yusufgurdogan/toss/internal/secure"
)

const (
	maxPendingHandshakes = 8
	handshakeTimeout     = 30 * time.Second
	dialTimeout          = 5 * time.Second
)

// clientHandshakeTimeout is shorter than the sender's handshakeTimeout:
// the receiver has other addresses to try. A variable for tests.
var clientHandshakeTimeout = 15 * time.Second

// Serve accepts connections on ln and runs the sender handshake on each,
// returning the first one that succeeds. It returns secure.ErrWrongCode as
// soon as someone tries a wrong code (the code is then burned), and
// secure.ErrLostAfterProof if the right receiver's connection broke at the
// very end of the handshake (the code is spent). notify, if
// set, receives errors from individual connections that don't end the wait
// (for example a receiver running another protocol version). ln is closed
// when Serve returns.
func Serve(ctx context.Context, ln net.Listener, srv *secure.Server, notify func(error)) (*tls.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// On return: stop accepting, cancel the handshakes still running
	// (another path from the same receiver, or a stranger), then wait.
	defer wg.Wait()
	defer cancel()
	defer ln.Close()

	type result struct {
		conn *tls.Conn
		err  error
	}
	results := make(chan result)
	acceptErr := make(chan error, 1)

	sem := make(chan struct{}, maxPendingHandshakes)
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			select {
			case sem <- struct{}{}:
			default:
				c.Close() // too many half-open attempts
				continue
			}
			wg.Go(func() {
				defer func() { <-sem }()
				hctx, hcancel := context.WithTimeout(ctx, handshakeTimeout)
				defer hcancel()
				tc, err := srv.Handshake(hctx, c)
				select {
				case results <- result{tc, err}:
				case <-ctx.Done():
					if tc != nil {
						tc.Close()
					}
				}
			})
		}
	})

	for {
		select {
		case r := <-results:
			switch {
			case r.err == nil:
				return r.conn, nil
			case errors.Is(r.err, secure.ErrWrongCode):
				return nil, r.err
			case errors.Is(r.err, secure.ErrLostAfterProof):
				return nil, r.err // the code is spent
			case notify != nil:
				notify(r.err)
			}
		case err := <-acceptErr:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("accepting connections: %w", err)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// DialOptions configures Dial.
type DialOptions struct {
	NoLAN   bool // don't search the local network
	LANPort int  // discovery port; 0 means lan.DefaultPort
	// LANTargets overrides where discovery queries go (tests).
	LANTargets []netip.AddrPort
	// Status, if set, is told about progress ("found the sender at ...").
	Status func(string)
}

// NotFoundError means no sender could be reached before the deadline.
type NotFoundError struct {
	Addr    string // the address from the code, if any
	LastErr error  // the last connection error, if any
}

func (e *NotFoundError) Error() string {
	if e.Addr != "" {
		if e.LastErr != nil {
			return fmt.Sprintf("couldn't reach the sender at %s: %v", e.Addr, e.LastErr)
		}
		return fmt.Sprintf("couldn't reach the sender at %s", e.Addr)
	}
	return "couldn't find the sender on this network"
}

// Dial finds the sender for code c and runs the receiver handshake. It
// tries the address in the code and every address LAN discovery finds,
// redialing each until ctx is done (the sender may not be up yet), and runs
// the handshake on connections one at a time as they open. A handshake error that
// may have consumed the code's single guess ends the search. When ctx's
// deadline passes first, the error is a *NotFoundError.
func Dial(ctx context.Context, c code.Code, opts DialOptions) (*tls.Conn, error) {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	status := func(s string) {
		if opts.Status != nil {
			opts.Status(s)
		}
	}

	conns := make(chan net.Conn)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		go func() {
			for c := range conns {
				c.Close()
			}
		}()
		wg.Wait()
		close(conns)
	}()

	var mu sync.Mutex
	var lastDialErr error
	offer := func(conn net.Conn) {
		select {
		case conns <- conn:
		case <-ctx.Done():
			conn.Close()
		}
	}
	dialer := &net.Dialer{Timeout: dialTimeout}

	// dialLoop keeps offering fresh connections to addr until the search
	// ends. offer blocks while a handshake is running, so there is at most
	// one spare connection per address; if a handshake fails before the
	// code was used (a stalled or foreign peer, a busy sender), the next
	// one is ready.
	dialLoop := func(addr string) {
		for {
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				offer(conn)
			} else {
				mu.Lock()
				lastDialErr = err
				mu.Unlock()
			}
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return
			}
		}
	}

	if c.Addr != "" {
		wg.Go(func() { dialLoop(c.Addr) })
	}
	if !opts.NoLAN {
		found, err := lan.Find(ctx, c.MeetingID(), lan.FindOptions{Port: opts.LANPort, Targets: opts.LANTargets})
		if err != nil {
			if c.Addr == "" {
				return nil, err
			}
			status("Local network search unavailable: " + err.Error())
		} else {
			wg.Go(func() {
				for ap := range found {
					wg.Go(func() { dialLoop(ap.String()) })
				}
			})
		}
	}

	var lastErr error
	for {
		select {
		case conn := <-conns:
			status("Found the sender at " + conn.RemoteAddr().String())
			// A peer that stalls must not hold up the search.
			hctx, hcancel := context.WithTimeout(ctx, clientHandshakeTimeout)
			tc, err := secure.Client(hctx, conn, c.Password())
			hcancel()
			if err == nil {
				return tc, nil
			}
			var spe *secure.SentProofError
			var ve *secure.VersionError
			if errors.As(err, &spe) || errors.As(err, &ve) {
				return nil, err
			}
			lastErr = err // not a toss sender, or a broken connection: keep looking
		case <-ctx.Done():
			if parent.Err() != context.DeadlineExceeded {
				return nil, parent.Err()
			}
			mu.Lock()
			defer mu.Unlock()
			if lastErr == nil {
				lastErr = lastDialErr
			}
			return nil, &NotFoundError{Addr: c.Addr, LastErr: lastErr}
		}
	}
}
