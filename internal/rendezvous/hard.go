package rendezvous

import (
	"context"
	"crypto/tls"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Symmetric ("hard") NATs give every destination a new public port, so the
// port the DHT saw is useless to the peer. The way through is a birthday
// attack (as Tailscale does it): the hard side sends from many sockets,
// creating many random public ports, and the other side sends to many
// random ports on the hard side's address; with 256 sockets and 1024
// guesses a round, some pair meets about 98% of the time.
//
// The first packets across follow the same rule as the rest of this
// package: the receiver's go out with a short TTL so they only open its own
// NAT, and the sender sends at full TTL. Two hard NATs facing each other
// remain out of reach.
const (
	hardSockets  = 256
	sprayGuesses = 1024
	sprayRounds  = 4
	sprayEvery   = 10 * time.Second
	// firstGuesses is the receiver's one round of guesses at a symmetric
	// sender, all sent before the receiver announces itself: once the
	// sender's sockets start sending, our router remembers their ports as
	// unsolicited and later guesses at them clash. 2048 guesses against
	// 256 sockets meet with a probability of about 99.97%.
	firstGuesses = 2048
	// hardStartDelay gives the receiver time to see a symmetric sender's
	// marker (and guess) before the sender's sockets start sending, when
	// the sender only found out late that its NAT is symmetric.
	hardStartDelay = 5 * time.Second
	// hardSafeGap: a receiver found more than this after our marker went
	// out looked us up after the marker (lookup plus poll take less).
	hardSafeGap = 6 * time.Second
	// maxSprayTargets bounds how many addresses one side guesses ports on.
	// Anyone who can see the meeting in the DHT could announce a fake
	// "symmetric" peer at someone else's address; this keeps the packets
	// we can be made to send small (a few thousand tiny probes).
	maxSprayTargets = 2
	// selfHardPorts is how many different public ports DHT nodes must
	// report for one socket before we decide our NAT is symmetric.
	selfHardPorts = 3
	// hardMarkPort is announced instead of a real port by a side behind a
	// symmetric NAT, so the other side knows to guess.
	hardMarkPort = 1
)

// selfHard reports whether our NAT gives different public ports to
// different destinations.
func selfHard(s *Socket) bool {
	return s.DHT.ExternalPorts() >= selfHardPorts
}

// peerPorts tells hard peers apart: a peer behind a symmetric NAT shows up
// in the DHT with one address and several ports (one per DHT node that
// stored its announcement).
type peerPorts struct {
	mu    sync.Mutex
	ports map[netip.Addr]map[uint16]bool
	hard  map[netip.Addr]bool
}

// sprayBudget limits port guessing per side and meeting.
type sprayBudget struct {
	mu      sync.Mutex
	targets map[netip.Addr]bool
}

// take reports whether guessing at ip is allowed.
func (b *sprayBudget) take(ip netip.Addr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.targets == nil {
		b.targets = map[netip.Addr]bool{}
	}
	if b.targets[ip] || len(b.targets) >= maxSprayTargets {
		return false
	}
	b.targets[ip] = true
	return true
}

// add records an address and reports whether this made its IP look hard
// for the first time.
func (pp *peerPorts) add(p netip.AddrPort) bool {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	if pp.ports == nil {
		pp.ports = map[netip.Addr]map[uint16]bool{}
		pp.hard = map[netip.Addr]bool{}
	}
	ip := p.Addr()
	if pp.ports[ip] == nil {
		pp.ports[ip] = map[uint16]bool{}
	}
	pp.ports[ip][p.Port()] = true
	if len(pp.ports[ip]) >= 2 && !pp.hard[ip] {
		pp.hard[ip] = true
		return true
	}
	return false
}

// spray sends probes to random ports on ip, in rounds, at the given TTL
// (0 means the normal TTL).
func spray(ctx context.Context, s *Socket, ip netip.Addr, role byte, tag [16]byte, ttl int, done <-chan struct{}) {
	p := makeProbe(role, tag)
	for round := 0; round < sprayRounds; round++ {
		for i := 0; i < sprayGuesses; i++ {
			to := netip.AddrPortFrom(ip, uint16(1024+rand.IntN(65536-1024)))
			if ttl > 0 {
				if s.WriteTTL(p, to, ttl) != nil {
					s.WriteTo(p, to)
				}
			} else {
				s.WriteTo(p, to)
			}
			if i%64 == 63 { // spread each round over about a second
				select {
				case <-time.After(60 * time.Millisecond):
				case <-ctx.Done():
					return
				case <-done:
					return
				}
			}
		}
		select {
		case <-time.After(sprayEvery):
		case <-ctx.Done():
			return
		case <-done:
			return
		}
	}
}

// guessOnce sends one round of short-TTL guesses at random ports on ip,
// all at once.
func guessOnce(s *Socket, ip netip.Addr, role byte, tag [16]byte, ttl, n int) {
	to := make([]netip.AddrPort, n)
	for i := range to {
		to[i] = netip.AddrPortFrom(ip, uint16(1024+rand.IntN(65536-1024)))
	}
	if s.WriteTTLMany(makeProbe(role, tag), to, ttl) != nil {
		for _, a := range to { // no TTL control here: send them plainly
			s.WriteTo(makeProbe(role, tag), a)
		}
	}
}

// hardSet is the extra sockets a hard side sends from.
type hardSet struct {
	once  sync.Once
	socks []*Socket
}

// open opens the sockets (once), next to main, and calls setup on each.
func (h *hardSet) open(main *Socket, opts *Options, setup func(*Socket)) []*Socket {
	h.once.Do(func() {
		bind := opts.Bind4
		if main.V6 {
			bind = opts.Bind6
		}
		if bind != "" {
			if ap, err := netip.ParseAddrPort(bind); err == nil {
				bind = netip.AddrPortFrom(ap.Addr(), 0).String()
			}
		}
		for range hardSockets {
			s, err := Open(main.V6, bind)
			if err != nil {
				break // out of file descriptors, say: use what we have
			}
			setup(s)
			h.socks = append(h.socks, s)
		}
	})
	return h.socks
}

func (h *hardSet) close() {
	for _, s := range h.socks {
		s.Close()
	}
}

// senderHardSocket prepares one of a hard sender's extra sockets: it
// listens for QUIC and answers the receiver's probes.
func senderHardSocket(ctx context.Context, s *Sender, sock *Socket, tag [16]byte, tlsConf *tls.Config, qconf *quic.Config) {
	ln, err := sock.Transport.Listen(tlsConf, qconf)
	if err != nil {
		return
	}
	sock.SetProbeHandler(func(role byte, t [16]byte, from netip.AddrPort) {
		if role == roleReceiver && t == tag {
			sock.WriteTo(makeProbe(roleSender, tag), from)
		}
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
}

// receiverHardSocket prepares one of a hard receiver's extra sockets: when
// the sender's probe gets through to it, it answers and dials QUIC from it.
func receiverHardSocket(ctx context.Context, r *Receiver, sock *Socket, tag [16]byte, tlsConf *tls.Config, qconf *quic.Config) {
	var once sync.Once
	sock.SetProbeHandler(func(role byte, t [16]byte, from netip.AddrPort) {
		if role != roleSender || t != tag {
			return
		}
		sock.WriteTo(makeProbe(roleReceiver, tag), from)
		once.Do(func() {
			r.wg.Go(func() {
				c, err := sock.Transport.Dial(ctx, net.UDPAddrFromAddrPort(from), tlsConf, qconf)
				if err != nil {
					return
				}
				select {
				case r.conns <- c:
				case <-ctx.Done():
					c.CloseWithError(0, "")
				}
			})
		})
	})
}

// punchFrom sends probes from each of socks to one address: at ttl (0 for
// the normal TTL), every second for punchFor or until done.
func punchFrom(ctx context.Context, socks []*Socket, to netip.AddrPort, role byte, tag [16]byte, ttl int, done <-chan struct{}) {
	p := makeProbe(role, tag)
	start := time.Now()
	for time.Since(start) < punchFor {
		for _, s := range socks {
			if ttl > 0 {
				if s.WriteTTL(p, to, ttl) != nil {
					s.WriteTo(p, to)
				}
			} else {
				s.WriteTo(p, to)
			}
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		case <-done:
			return
		}
	}
}
