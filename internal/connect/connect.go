// Package connect establishes the secure connection between a toss sender
// and receiver. The sender accepts connections (TCP on the local network or
// at a given address, QUIC from receivers met through the DHT) and runs
// the code check on each until one succeeds. The receiver tries every way
// to reach the sender at once and runs the code check on one connection at
// a time, stopping at the first failure that may have used its one guess.
package connect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/yusufgurdogan/toss/internal/code"
	"github.com/yusufgurdogan/toss/internal/lan"
	"github.com/yusufgurdogan/toss/internal/qconn"
	"github.com/yusufgurdogan/toss/internal/rendezvous"
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

// Conn is an established, authenticated connection: a *tls.Conn over TCP
// or a *qconn.Conn over QUIC.
type Conn interface {
	io.ReadWriteCloser
	RemoteAddr() net.Addr
}

// Serve accepts connections on ln (TCP, may be nil) and from rv (QUIC
// connections from receivers met through the DHT, may be nil), runs the
// code check on each and returns the first that passes. It returns
// secure.ErrWrongCode as soon as someone tries a wrong code (the code is
// then burned), and secure.ErrLostAfterProof if the right receiver's
// connection broke at the very end of the check (the code is spent).
// notify, if set, receives errors from single connections that don't end
// the wait (for example a receiver running another protocol version). ln
// is closed when Serve returns.
func Serve(ctx context.Context, ln net.Listener, rv *rendezvous.Sender, srv *secure.Server, notify func(error)) (Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// On return: stop accepting, cancel the checks still running (another
	// path from the same receiver, or a stranger), then wait.
	defer wg.Wait()
	defer cancel()
	if ln != nil {
		defer ln.Close()
	}

	type result struct {
		conn Conn
		err  error
	}
	results := make(chan result)
	acceptErr := make(chan error, 1)
	sem := make(chan struct{}, maxPendingHandshakes)
	deliver := func(c Conn, err error) {
		select {
		case results <- result{c, err}:
		case <-ctx.Done():
			if c != nil {
				c.Close()
			}
		}
	}

	if ln != nil {
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
					if err != nil {
						deliver(nil, err)
						return
					}
					deliver(tc, nil)
				})
			}
		})
	}
	if rv != nil {
		wg.Go(func() {
			for {
				var qc *quic.Conn
				select {
				case qc = <-rv.Conns():
				case <-ctx.Done():
					return
				}
				select {
				case sem <- struct{}{}:
				default:
					qc.CloseWithError(0, "busy")
					continue
				}
				wg.Go(func() {
					defer func() { <-sem }()
					c, err := serveQUIC(ctx, qc, srv)
					if err != nil {
						deliver(nil, err)
						return
					}
					deliver(c, nil)
				})
			}
		})
	}

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

// serveQUIC runs the sender's code check on the first stream of qc.
func serveQUIC(ctx context.Context, qc *quic.Conn, srv *secure.Server) (Conn, error) {
	hctx, hcancel := context.WithTimeout(ctx, handshakeTimeout)
	defer hcancel()
	st, err := qc.AcceptStream(hctx)
	if err != nil {
		qc.CloseWithError(0, "")
		return nil, err
	}
	st.SetDeadline(time.Now().Add(handshakeTimeout))
	ekm, err := secure.Exporter(qc.ConnectionState().TLS)
	if err == nil {
		err = srv.HandshakeStream(st, ekm)
	}
	if err != nil {
		// Close gracefully so the status we may have just written ("wrong
		// code", "refused") reaches the receiver: an abrupt QUIC close
		// would discard it.
		st.SetDeadline(time.Time{})
		qconn.New(qc, st).Close()
		return nil, err
	}
	st.SetDeadline(time.Time{})
	return qconn.New(qc, st), nil
}

// DialOptions configures Dial.
type DialOptions struct {
	NoLAN   bool // don't search the local network
	LANPort int  // discovery port; 0 means lan.DefaultPort
	// LANTargets overrides where discovery queries go (tests).
	LANTargets []netip.AddrPort
	// NoDHT skips meeting the sender through the internet (the DHT).
	NoDHT bool
	// Rendezvous configures the internet meeting (tests).
	Rendezvous rendezvous.Options
	// Status, if set, is told about progress.
	Status func(string)
}

// NotFoundError means no sender could be reached before the deadline.
type NotFoundError struct {
	Addr string // the address from the code, if any
	// FoundOnline is how many addresses for the sender the internet
	// meeting point returned. Non-zero means the sender was found but no
	// direct connection could be opened between the two networks.
	FoundOnline int
	LastErr     error // the last connection error, if any
}

func (e *NotFoundError) Error() string {
	switch {
	case e.Addr != "" && e.LastErr != nil:
		return fmt.Sprintf("couldn't reach the sender at %s: %v", e.Addr, e.LastErr)
	case e.Addr != "":
		return fmt.Sprintf("couldn't reach the sender at %s", e.Addr)
	case e.FoundOnline > 0:
		return "found the sender, but couldn't open a direct connection between your networks"
	}
	return "couldn't find the sender"
}

// candidate is a connection to check the code on: TCP (secure.Client does
// TLS and the check) or QUIC (TLS already done).
type candidate struct {
	tcp  net.Conn
	quic *quic.Conn
}

func (c candidate) close() {
	if c.tcp != nil {
		c.tcp.Close()
	}
	if c.quic != nil {
		c.quic.CloseWithError(0, "")
	}
}

func (c candidate) remote() net.Addr {
	if c.tcp != nil {
		return c.tcp.RemoteAddr()
	}
	return c.quic.RemoteAddr()
}

// Dial finds the sender for code c and runs the receiver's code check. It
// tries everything at once: the address in the code, the local network,
// and the internet meeting point (DHT, hole punching, QUIC), redialing
// until ctx is done in case the sender isn't up yet. The code check runs on
// one connection at a time; a failure that may have used the code's one
// guess ends the search. When ctx's deadline passes first, the error is a
// *NotFoundError.
func Dial(ctx context.Context, c code.Code, opts DialOptions) (Conn, error) {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	status := func(s string) {
		if opts.Status != nil {
			opts.Status(s)
		}
	}

	cands := make(chan candidate)
	var wg sync.WaitGroup
	var rv *rendezvous.Receiver
	keepRV := false
	defer func() {
		cancel()
		go func() {
			for c := range cands {
				c.close()
			}
		}()
		wg.Wait()
		close(cands)
		if rv != nil && !keepRV {
			rv.Close()
		}
	}()

	var mu sync.Mutex
	var lastDialErr error
	offer := func(cd candidate) {
		select {
		case cands <- cd:
		case <-ctx.Done():
			cd.close()
		}
	}
	dialer := &net.Dialer{Timeout: dialTimeout}

	// dialLoop keeps offering fresh connections to addr until the search
	// ends. offer blocks while a check is running, so there is at most one
	// spare connection per address; if a check fails before the code was
	// used (a stalled or foreign peer, a busy sender), the next is ready.
	dialLoop := func(addr string) {
		for {
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				offer(candidate{tcp: conn})
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
		if err == nil {
			wg.Go(func() {
				for ap := range found {
					wg.Go(func() { dialLoop(ap.String()) })
				}
			})
		}
	}
	if !opts.NoDHT {
		var err error
		rv, err = rendezvous.StartReceiver(ctx, c.MeetingID(), secure.ClientTLSConfig(), qconn.Config(), opts.Rendezvous)
		if err != nil {
			status("Can't use the internet meeting point: " + err.Error())
		} else {
			wg.Go(func() {
				for {
					select {
					case qc := <-rv.Conns():
						offer(candidate{quic: qc})
					case <-ctx.Done():
						return
					}
				}
			})
		}
	}

	var lastErr error
	for {
		select {
		case cd := <-cands:
			status("Found the sender at " + cd.remote().String())
			// A peer that stalls must not hold up the search.
			hctx, hcancel := context.WithTimeout(ctx, clientHandshakeTimeout)
			conn, err := checkCode(hctx, cd, c.Password())
			hcancel()
			if err == nil {
				if cd.quic != nil {
					// The connection runs over the meeting's sockets:
					// keep them until it's closed.
					keepRV = true
					rv.Stop()
					return &closeHook{Conn: conn, after: rv.Close}, nil
				}
				return conn, nil
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
			nf := &NotFoundError{Addr: c.Addr, LastErr: lastErr}
			if rv != nil {
				nf.FoundOnline = rv.Found()
			}
			return nil, nf
		}
	}
}

// checkCode runs the receiver's side of the code check on a candidate.
func checkCode(ctx context.Context, cd candidate, password string) (Conn, error) {
	if cd.tcp != nil {
		return secure.Client(ctx, cd.tcp, password)
	}
	st, err := cd.quic.OpenStreamSync(ctx)
	if err != nil {
		cd.close()
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	st.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { st.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	ekm, err := secure.Exporter(cd.quic.ConnectionState().TLS)
	if err == nil {
		err = secure.ClientStream(st, ekm, password)
	}
	if err != nil {
		cd.close()
		return nil, err
	}
	st.SetDeadline(time.Time{})
	return qconn.New(cd.quic, st), nil
}

// closeHook runs after once the connection is closed.
type closeHook struct {
	Conn
	once  sync.Once
	after func()
}

func (c *closeHook) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.after)
	return err
}

// CloseWrite passes through to connections that support it.
func (c *closeHook) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}
