// Package rendezvous lets a toss sender and receiver on different networks
// find each other and open a direct connection, with no server of their
// own: they meet in the BitTorrent DHT, punch through their NATs and
// firewalls with UDP probes, and connect with QUIC over the same sockets.
//
// The sender announces itself under a hash of the code's public part (the
// meeting ID) and the receiver under a different hash of it; each looks
// the other up. DHT nodes record the address and port they see, which is
// the NAT's public mapping of the socket. Both sides then send probes to
// each other's mapping: the outgoing probe makes each NAT accept the other
// side's packets. The receiver dials QUIC once a path looks open.
//
// Nothing here is trusted: anyone can announce under the same hash or send
// probes. The code check that runs inside each QUIC connection decides who
// the real peer is, and still allows only one guess per code.
package rendezvous

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/yusufgurdogan/toss/internal/dht"
)

// Options configures the meeting. The zero value is right for real use.
type Options struct {
	// Bind4 and Bind6 are local addresses for the IPv4 and IPv6 sockets
	// ("" for any). NoIPv6 skips IPv6.
	Bind4, Bind6 string
	NoIPv6       bool
	// Bootstrap and AllowPrivate configure the DHT clients (tests run a
	// fake DHT on loopback).
	Bootstrap    []string
	AllowPrivate bool
	// Poll is how often each side looks for the other (default 2s).
	Poll time.Duration
	// Event, if set, is told about progress.
	Event func(Event)
}

// Event describes progress, for status messages and diagnostics.
type Event struct {
	Kind string         // "published", "found", "dht-error"
	Addr netip.AddrPort // the address concerned, if any
	Err  error
}

func (o *Options) poll() time.Duration {
	if o.Poll == 0 {
		return 2 * time.Second
	}
	return o.Poll
}

func (o *Options) event(e Event) {
	if o.Event != nil {
		o.Event(e)
	}
}

const (
	reannounce   = 4 * time.Minute // DHT nodes forget announcements after ~30 min
	fullLookup   = time.Minute     // between full lookups; quick re-checks in between
	punchFast    = 200 * time.Millisecond
	punchFastFor = 5 * time.Second
	punchSlow    = time.Second
	punchFor     = 2 * time.Minute
	maxEndpoints = 16 // per socket: bounds work spent on fake announcements
)

const (
	roleSender   byte = 's'
	roleReceiver byte = 'r'
)

// meeting holds what both sides derive from the meeting ID.
type meeting struct {
	senderKey, receiverKey dht.ID
	tag                    [16]byte
}

func newMeeting(meetingID string) meeting {
	m := meeting{
		senderKey:   dht.HashOf("toss/1 sender " + meetingID),
		receiverKey: dht.HashOf("toss/1 receiver " + meetingID),
	}
	sum := sha256.Sum256([]byte("toss/1 probe " + meetingID))
	copy(m.tag[:], sum[:])
	return m
}

func openSockets(opts *Options) ([]*Socket, error) {
	var socks []*Socket
	s4, err4 := Open(false, opts.Bind4)
	if err4 == nil {
		socks = append(socks, s4)
	}
	if !opts.NoIPv6 {
		if s6, err := Open(true, opts.Bind6); err == nil {
			socks = append(socks, s6)
		}
	}
	if len(socks) == 0 {
		return nil, err4
	}
	for _, s := range socks {
		s.DHT.AllowPrivate = opts.AllowPrivate
		s.DHT.Bootstrap = opts.Bootstrap
	}
	return socks, nil
}

// punch sends probes to an address: fast at first, then slowly to keep
// the NAT mappings open, until ctx ends or punchFor has passed.
func punch(ctx context.Context, s *Socket, to netip.AddrPort, role byte, tag [16]byte) {
	p := makeProbe(role, tag)
	start := time.Now()
	for time.Since(start) < punchFor {
		s.WriteTo(p, to)
		wait := punchFast
		if time.Since(start) > punchFastFor {
			wait = punchSlow
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
	}
}

// watch looks up key on the DHT every poll and calls found once for each
// new address: a full lookup at first and every fullLookup, quick
// re-checks of the closest nodes in between.
func watch(ctx context.Context, s *Socket, key dht.ID, opts *Options, found func(netip.AddrPort)) {
	seen := map[netip.AddrPort]bool{}
	var closest []dht.Contact
	var last time.Time
	for {
		var peers []netip.AddrPort
		if closest == nil || time.Since(last) > fullLookup {
			res, err := s.DHT.FindPeers(ctx, key)
			if err != nil {
				opts.event(Event{Kind: "dht-error", Err: err})
			} else {
				peers, closest, last = res.Peers, res.Closest, time.Now()
				s.DHT.Save()
			}
		} else {
			peers = s.DHT.GetPeersFrom(ctx, key, closest)
		}
		for _, p := range peers {
			if !seen[p] && len(seen) < maxEndpoints {
				seen[p] = true
				found(p)
			}
		}
		select {
		case <-time.After(opts.poll()):
		case <-ctx.Done():
			return
		}
	}
}

// announce publishes this socket under key, and again every reannounce.
// Behind a symmetric NAT the public port the DHT nodes see is useless to
// the peer, so we announce hardMarkPort instead, which tells the peer to
// guess ports (see hard.go). If we find out later that our NAT is
// symmetric we announce again at once; markedAt records when the marker
// first went out.
func announce(ctx context.Context, s *Socket, key dht.ID, opts *Options, markedAt *atomic.Int64) {
	announcedHard := false
	for {
		res, err := s.DHT.GetPeers(ctx, key)
		hard := err == nil && selfHard(s)
		port, implied := 0, true
		if hard {
			port, implied = hardMarkPort, false
		}
		if err == nil && s.DHT.Announce(ctx, key, res.Closest, port, implied) > 0 {
			announcedHard = hard
			if hard && markedAt != nil {
				markedAt.CompareAndSwap(0, time.Now().UnixNano())
			}
			ext, _ := s.DHT.External()
			opts.event(Event{Kind: "published", Addr: ext})
			s.DHT.Save()
		} else if err != nil && ctx.Err() == nil {
			opts.event(Event{Kind: "dht-error", Err: err})
		}
		wait := reannounce
		if err != nil {
			wait = 10 * time.Second
		}
		for end := time.Now().Add(wait); time.Now().Before(end); {
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return
			}
			if err == nil && selfHard(s) != announcedHard {
				break // our NAT turned out to be symmetric: say so now
			}
		}
	}
}

// Sender publishes the sender in the DHT, punches towards every receiver
// it finds there, and accepts their QUIC connections.
type Sender struct {
	opts   Options
	socks  []*Socket
	hard   []*hardSet
	conns  chan *quic.Conn
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// StartSender starts meeting receivers for meetingID. tlsConf is the
// sender's TLS configuration (from secure.Server).
func StartSender(ctx context.Context, meetingID string, tlsConf *tls.Config, qconf *quic.Config, opts Options) (*Sender, error) {
	socks, err := openSockets(&opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Sender{opts: opts, socks: socks, conns: make(chan *quic.Conn), cancel: cancel}
	m := newMeeting(meetingID)
	for _, sock := range socks {
		ln, err := sock.Transport.Listen(tlsConf, qconf)
		if err != nil {
			s.Close()
			return nil, err
		}
		var mu sync.Mutex
		punching := map[netip.AddrPort]bool{}
		startPunch := func(to netip.AddrPort) {
			mu.Lock()
			defer mu.Unlock()
			if punching[to] || len(punching) >= 2*maxEndpoints {
				return
			}
			punching[to] = true
			s.wg.Go(func() { punch(ctx, sock, to, roleSender, m.tag) })
		}
		sock.SetProbeHandler(func(role byte, tag [16]byte, from netip.AddrPort) {
			if role != roleReceiver || tag != m.tag {
				return
			}
			sock.WriteTo(makeProbe(roleSender, m.tag), from)
			startPunch(from) // its NAT may use another port towards us
		})
		s.wg.Go(func() {
			for {
				c, err := ln.Accept(ctx)
				if err != nil {
					return
				}
				select {
				case s.conns <- c:
				case <-ctx.Done():
					c.CloseWithError(0, "")
					return
				}
			}
		})
		var markedAt atomic.Int64
		s.wg.Go(func() { announce(ctx, sock, m.senderKey, &s.opts, &markedAt) })
		var pp peerPorts
		var budget sprayBudget
		hard := &hardSet{}
		s.hard = append(s.hard, hard)
		var known []netip.AddrPort // receivers with a usable port
		hardPunched := map[netip.AddrPort]bool{}
		// hardPunch sends from many sockets (so many public ports) to a
		// receiver, once our NAT is known to be symmetric and the
		// receiver has had time to see our marker and guess.
		hardPunch := func(p netip.AddrPort) {
			mu.Lock()
			if hardPunched[p] {
				mu.Unlock()
				return
			}
			hardPunched[p] = true
			mu.Unlock()
			foundAt := time.Now()
			s.wg.Go(func() {
				for {
					// The receiver guesses our ports before announcing
					// itself, if it saw our marker by then. That's certain
					// when the marker went out well before we found it;
					// otherwise give it time to see the marker and guess.
					at := markedAt.Load()
					marked := time.Unix(0, at)
					if at != 0 && (foundAt.Sub(marked) > hardSafeGap || time.Since(marked) >= hardStartDelay) {
						break
					}
					select {
					case <-time.After(250 * time.Millisecond):
					case <-ctx.Done():
						return
					}
				}
				socks := hard.open(sock, &s.opts, func(hs *Socket) {
					senderHardSocket(ctx, s, hs, m.tag, tlsConf, qconf)
				})
				s.opts.event(Event{Kind: "own-hard-nat", Addr: p})
				punchFrom(ctx, socks, p, roleSender, m.tag, 0, nil)
			})
		}
		s.wg.Go(func() {
			watch(ctx, sock, m.receiverKey, &s.opts, func(p netip.AddrPort) {
				s.opts.event(Event{Kind: "found", Addr: p})
				peerHard := pp.add(p) || p.Port() == hardMarkPort
				if p.Port() != hardMarkPort {
					startPunch(p)
				}
				if peerHard && budget.take(p.Addr()) {
					// The receiver's NAT is symmetric: guess its ports.
					s.opts.event(Event{Kind: "peer-hard-nat", Addr: p})
					s.wg.Go(func() { spray(ctx, sock, p.Addr(), roleSender, m.tag, 0, nil) })
				}
				if !peerHard {
					mu.Lock()
					known = append(known, p)
					mu.Unlock()
					if selfHard(sock) {
						hardPunch(p)
					}
				}
			})
		})
		// We may learn only later that our NAT is symmetric.
		s.wg.Go(func() {
			for {
				select {
				case <-time.After(2 * time.Second):
				case <-ctx.Done():
					return
				}
				if !selfHard(sock) {
					continue
				}
				mu.Lock()
				list := append([]netip.AddrPort(nil), known...)
				mu.Unlock()
				for _, p := range list {
					hardPunch(p)
				}
			}
		})
	}
	return s, nil
}

// Conns delivers incoming QUIC connections (TLS done, code not checked).
func (s *Sender) Conns() <-chan *quic.Conn { return s.conns }

// Stop stops publishing, punching and accepting. Connections already
// accepted keep working until Close.
func (s *Sender) Stop() {
	s.cancel()
	s.wg.Wait()
}

// Close stops everything and closes the sockets, ending any connection
// that runs over them.
func (s *Sender) Close() {
	s.Stop()
	for _, sock := range s.socks {
		sock.Close()
	}
	for _, h := range s.hard {
		h.close()
	}
}

// Receiver publishes the receiver in the DHT, looks for the sender there,
// punches towards it and dials QUIC.
type Receiver struct {
	opts     Options
	socks    []*Socket
	hard     []*hardSet
	conns    chan *quic.Conn
	found    atomic.Int32
	selfHard atomic.Bool // our NAT is symmetric
	peerHard atomic.Bool // the sender's NAT is symmetric
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// StartReceiver starts looking for the sender of meetingID. tlsConf is the
// receiver's TLS configuration (from secure.ClientTLSConfig).
func StartReceiver(ctx context.Context, meetingID string, tlsConf *tls.Config, qconf *quic.Config, opts Options) (*Receiver, error) {
	socks, err := openSockets(&opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &Receiver{opts: opts, socks: socks, conns: make(chan *quic.Conn), cancel: cancel}
	m := newMeeting(meetingID)
	for _, sock := range socks {
		var mu sync.Mutex
		dialing := map[netip.AddrPort]bool{}
		punching := map[netip.AddrPort]bool{}
		laddering := map[netip.AddrPort]bool{}
		opened := make(chan struct{}) // closed when a sender probe gets through
		var openOnce sync.Once
		found := make(chan struct{}) // closed when the DHT returns the sender
		var foundOnce sync.Once

		dial := func(to netip.AddrPort) {
			mu.Lock()
			if dialing[to] || len(dialing) >= 2*maxEndpoints {
				mu.Unlock()
				return
			}
			dialing[to] = true
			mu.Unlock()
			r.wg.Go(func() {
				c, err := sock.Transport.Dial(ctx, net.UDPAddrFromAddrPort(to), tlsConf, qconf)
				if err != nil {
					mu.Lock()
					delete(dialing, to) // a later probe may try again
					mu.Unlock()
					return
				}
				select {
				case r.conns <- c:
				case <-ctx.Done():
					c.CloseWithError(0, "")
				}
			})
		}
		startPunch := func(to netip.AddrPort) {
			mu.Lock()
			defer mu.Unlock()
			if punching[to] || len(punching) >= 2*maxEndpoints {
				return
			}
			punching[to] = true
			r.wg.Go(func() { punch(ctx, sock, to, roleReceiver, m.tag) })
		}
		sock.SetProbeHandler(func(role byte, tag [16]byte, from netip.AddrPort) {
			if role != roleSender || tag != m.tag {
				return
			}
			// The sender's packets get through, so its NAT has a mapping
			// towards us: now we can answer at full TTL and connect.
			openOnce.Do(func() { close(opened) })
			sock.WriteTo(makeProbe(roleReceiver, m.tag), from)
			startPunch(from)
			dial(from)
		})
		// Publish ourselves only after the short-lived probes towards the
		// sender have opened our own NAT: then the sender's first packets
		// to us are expected, wherever they arrive first.
		r.wg.Go(func() {
			select {
			case <-found:
				announce(ctx, sock, m.receiverKey, &r.opts, nil)
			case <-ctx.Done():
			}
		})
		var pp peerPorts
		var budget sprayBudget
		hard := &hardSet{}
		r.hard = append(r.hard, hard)
		var known []netip.AddrPort // senders with a usable port
		hardPunched := map[netip.AddrPort]bool{}
		// hardPunch sends short-TTL probes from many sockets to a sender,
		// once our NAT is known to be symmetric. Our announcement (with
		// the marker) follows, and the sender then guesses at us.
		hardPunch := func(p netip.AddrPort) {
			mu.Lock()
			if hardPunched[p] {
				mu.Unlock()
				return
			}
			hardPunched[p] = true
			mu.Unlock()
			socks := hard.open(sock, &r.opts, func(hs *Socket) {
				receiverHardSocket(ctx, r, hs, m.tag, tlsConf, qconf)
			})
			r.opts.event(Event{Kind: "own-hard-nat", Addr: p})
			for _, hs := range socks { // the first probes go out now
				hs.WriteTTL(makeProbe(roleReceiver, m.tag), p, ladderStart)
			}
			r.wg.Go(func() { punchFrom(ctx, socks, p, roleReceiver, m.tag, ladderStart, opened) })
		}
		r.wg.Go(func() {
			for {
				select {
				case <-time.After(2 * time.Second):
				case <-ctx.Done():
					return
				}
				if !selfHard(sock) {
					continue
				}
				mu.Lock()
				list := append([]netip.AddrPort(nil), known...)
				mu.Unlock()
				for _, p := range list {
					hardPunch(p)
				}
			}
		})
		r.wg.Go(func() {
			watch(ctx, sock, m.senderKey, &r.opts, func(p netip.AddrPort) {
				r.found.Add(1)
				r.opts.event(Event{Kind: "found", Addr: p})
				// Symmetric NATs (see hard.go). All of this goes out at a
				// short TTL, before we announce ourselves.
				peerHard := pp.add(p) || p.Port() == hardMarkPort
				if peerHard {
					r.peerHard.Store(true)
				}
				if selfHard(sock) {
					r.selfHard.Store(true)
				}
				if peerHard && budget.take(p.Addr()) {
					// One big round of guesses, done before we announce
					// ourselves (the sender starts sending when it finds us).
					r.opts.event(Event{Kind: "peer-hard-nat", Addr: p})
					guessOnce(sock, p.Addr(), roleReceiver, m.tag, ladderStart, firstGuesses)
				}
				if !peerHard {
					mu.Lock()
					known = append(known, p)
					mu.Unlock()
					if selfHard(sock) {
						hardPunch(p)
					}
				}
				mu.Lock()
				dup := laddering[p]
				laddering[p] = true
				mu.Unlock()
				if p.Port() == hardMarkPort {
					// Nothing to punch at: the guessing above does the work.
					foundOnce.Do(func() { close(found) })
					return
				}
				if dup {
					return
				}
				// Open our NAT towards the sender before anything
				// announces us, then ladder up if nothing comes back.
				sock.WriteTTL(makeProbe(roleReceiver, m.tag), p, ladderStart)
				foundOnce.Do(func() { close(found) })
				r.wg.Go(func() {
					if !punchLadder(ctx, sock, p, m.tag, opened) {
						return
					}
					startPunch(p)
					dial(p)
				})
			})
		})
	}
	return r, nil
}

// The TTL ladder. Linux-based routers (most home routers) create a
// connection-tracking entry when a packet arrives before their host has
// sent anything to that peer; the host's own packets to the peer then get
// a different public port, and neither side's packets get through. So the
// receiver's first probes expire after ladderStart hops: enough to pass
// its own router, not enough to reach the sender's across the internet.
// The sender, which only learns our address after these went out, sends
// at full TTL; its packets find our NAT open and its own NAT sees its
// packets go out first. If no sender probe arrives (say a carrier-grade
// NAT further up needs opening too), the TTL creeps up, then goes to full.
const ladderStart = 2

var ladderSteps = []struct {
	ttl int
	dur time.Duration
}{
	{2, 6 * time.Second},
	{3, time.Second}, {4, time.Second}, {5, time.Second}, {6, time.Second},
	{8, time.Second}, {12, time.Second}, {16, time.Second},
}

// punchLadder sends short-lived probes to the sender until one of its
// probes gets through (opened) or the ladder ends. It reports whether to
// go on with full-TTL probes and a QUIC dial; false means the probe
// handler already did, or ctx ended.
func punchLadder(ctx context.Context, s *Socket, to netip.AddrPort, tag [16]byte, opened <-chan struct{}) bool {
	p := makeProbe(roleReceiver, tag)
	for _, step := range ladderSteps {
		end := time.Now().Add(step.dur)
		for time.Now().Before(end) {
			if err := s.WriteTTL(p, to, step.ttl); err != nil {
				return true // can't limit TTL here: just go ahead
			}
			select {
			case <-opened:
				return false
			case <-ctx.Done():
				return false
			case <-time.After(punchFast):
			}
		}
	}
	return true
}

// Conns delivers QUIC connections to possible senders (TLS done, code not
// checked yet).
func (r *Receiver) Conns() <-chan *quic.Conn { return r.conns }

// Found is how many sender addresses the DHT has returned so far.
func (r *Receiver) Found() int { return int(r.found.Load()) }

// BothHard reports whether both sides are behind symmetric NATs, which
// hole punching can't get through.
func (r *Receiver) BothHard() bool { return r.selfHard.Load() && r.peerHard.Load() }

// Stop stops looking, punching and dialing. Connections already
// delivered keep working until Close.
func (r *Receiver) Stop() {
	r.cancel()
	r.wg.Wait()
}

// Close stops everything and closes the sockets, ending any connection
// that runs over them.
func (r *Receiver) Close() {
	r.Stop()
	for _, sock := range r.socks {
		sock.Close()
	}
	for _, h := range r.hard {
		h.close()
	}
}
