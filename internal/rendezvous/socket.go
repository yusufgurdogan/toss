package rendezvous

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/yusufgurdogan/toss/internal/dht"
)

// Socket is one UDP socket shared by the DHT client, hole-punching probes
// and QUIC. Sharing matters: the address the DHT nodes see for this socket
// is the NAT mapping the peer must send to, and QUIC must use that same
// mapping.
//
// quic-go can't share a socket with the DHT by itself (KRPC messages start
// with "d", which looks like a QUIC packet), so the Socket reads every
// packet and routes it: KRPC to the DHT client, probes to the probe
// handler, everything else to QUIC.
type Socket struct {
	V6        bool
	DHT       *dht.Client
	Transport *quic.Transport

	udp     *net.UDPConn
	quicIn  chan packet
	done    chan struct{}
	closing sync.Once
	wg      sync.WaitGroup

	mu       sync.Mutex
	onProbe  func(role byte, tag [16]byte, from netip.AddrPort)
	deadline time.Time
	wake     chan struct{}

	// wmu lets a short-lived probe change the socket's TTL without other
	// packets (QUIC, DHT) going out with it: normal writes hold it shared.
	wmu    sync.RWMutex
	defTTL int
}

type packet struct {
	b    []byte
	from netip.AddrPort
}

// Open opens a socket for IPv4 or IPv6 on any free port, or on addr if
// given ("127.0.0.1:0" in tests).
func Open(v6 bool, addr string) (*Socket, error) {
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	var laddr *net.UDPAddr
	if addr != "" {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		laddr = net.UDPAddrFromAddrPort(ap)
	}
	udp, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	udp.SetReadBuffer(4 << 20)
	udp.SetWriteBuffer(4 << 20)
	s := &Socket{
		defTTL: 64,
		V6:     v6,
		udp:    udp,
		quicIn: make(chan packet, 4096),
		done:   make(chan struct{}),
		wake:   make(chan struct{}),
	}
	if rc, err := udp.SyscallConn(); err == nil {
		s.defTTL = getTTL(rc, v6)
	}
	s.DHT = dht.New(sharedWriter{s}, v6)
	s.Transport = &quic.Transport{Conn: (*quicConn)(s)}
	s.wg.Go(s.dispatch)
	return s, nil
}

// LocalAddr is the socket's local address.
func (s *Socket) LocalAddr() netip.AddrPort {
	return s.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

// WriteTo sends a raw packet.
func (s *Socket) WriteTo(b []byte, to netip.AddrPort) error {
	s.wmu.RLock()
	defer s.wmu.RUnlock()
	_, err := s.udp.WriteToUDPAddrPort(b, to)
	return err
}

// WriteTTL sends a packet that expires after ttl router hops. It opens a
// mapping in our own NAT without reaching the peer's (see punchLadder).
// If the TTL can't be changed the packet isn't sent.
func (s *Socket) WriteTTL(b []byte, to netip.AddrPort, ttl int) error {
	rc, err := s.udp.SyscallConn()
	if err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := setTTL(rc, s.V6, ttl); err != nil {
		return err
	}
	_, err = s.udp.WriteToUDPAddrPort(b, to)
	if rerr := setTTL(rc, s.V6, s.defTTL); err == nil {
		err = rerr
	}
	return err
}

// sharedWriter is how the DHT client writes: shared with QUIC, excluded
// from TTL changes.
type sharedWriter struct{ s *Socket }

func (w sharedWriter) WriteTo(b []byte, addr net.Addr) (int, error) {
	w.s.wmu.RLock()
	defer w.s.wmu.RUnlock()
	return w.s.udp.WriteTo(b, addr)
}

// SetProbeHandler sets the function called for each valid probe.
func (s *Socket) SetProbeHandler(h func(role byte, tag [16]byte, from netip.AddrPort)) {
	s.mu.Lock()
	s.onProbe = h
	s.mu.Unlock()
}

// Close closes QUIC, the DHT client and the socket.
func (s *Socket) Close() {
	s.closing.Do(func() {
		s.Transport.Close()
		close(s.done)
		s.udp.Close()
		s.wg.Wait()
	})
}

func (s *Socket) dispatch() {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // e.g. ICMP errors reported on the socket
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		b := buf[:n]
		switch {
		case dht.IsKRPC(b):
			s.DHT.Handle(b, from)
		case isProbe(b):
			var tag [16]byte
			copy(tag[:], b[7:])
			s.mu.Lock()
			h := s.onProbe
			s.mu.Unlock()
			if h != nil {
				h(b[6], tag, from)
			}
		default:
			p := packet{b: append([]byte(nil), b...), from: from}
			select {
			case s.quicIn <- p:
			default: // QUIC is behind; it will retransmit
			}
		}
	}
}

// Probes punch holes in NATs and firewalls: each side sends them to the
// other's public address, so that each side's NAT sees outgoing traffic
// and lets the other side's packets in. The first byte keeps them apart
// from QUIC packets. The tag ties them to one meeting; it's derived from
// the public part of the code only, so probes prove nothing by themselves
// (the code check inside QUIC does).
const probeLen = 1 + 5 + 1 + 16

func makeProbe(role byte, tag [16]byte) []byte {
	return append([]byte{0x01, 't', 'o', 's', 's', 'p', role}, tag[:]...)
}

func isProbe(b []byte) bool {
	return len(b) == probeLen && b[0] == 0x01 && string(b[1:6]) == "tossp"
}

// quicConn is the Socket as quic-go sees it: a net.PacketConn whose reads
// return only the packets routed to QUIC.
type quicConn Socket

func (q *quicConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		q.mu.Lock()
		dl, wake := q.deadline, q.wake
		q.mu.Unlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		stop := func() {
			if timer != nil {
				timer.Stop()
			}
		}
		select {
		case p := <-q.quicIn:
			stop()
			n := copy(b, p.b)
			return n, net.UDPAddrFromAddrPort(p.from), nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-wake:
			stop() // the deadline changed; look again
		case <-q.done:
			stop()
			return 0, nil, net.ErrClosed
		}
	}
}

func (q *quicConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	q.wmu.RLock()
	defer q.wmu.RUnlock()
	return q.udp.WriteTo(b, addr)
}

// Close is a no-op: the Socket owns the UDP socket.
func (q *quicConn) Close() error { return nil }

func (q *quicConn) LocalAddr() net.Addr { return q.udp.LocalAddr() }

func (q *quicConn) SetDeadline(t time.Time) error {
	q.SetReadDeadline(t)
	return q.udp.SetWriteDeadline(t)
}

func (q *quicConn) SetReadDeadline(t time.Time) error {
	q.mu.Lock()
	q.deadline = t
	close(q.wake)
	q.wake = make(chan struct{})
	q.mu.Unlock()
	return nil
}

func (q *quicConn) SetWriteDeadline(t time.Time) error { return q.udp.SetWriteDeadline(t) }

// quic-go sizes the socket buffers through these.
func (q *quicConn) SetReadBuffer(n int) error  { return q.udp.SetReadBuffer(n) }
func (q *quicConn) SetWriteBuffer(n int) error { return q.udp.SetWriteBuffer(n) }

func (q *quicConn) SyscallConn() (syscall.RawConn, error) { return q.udp.SyscallConn() }
