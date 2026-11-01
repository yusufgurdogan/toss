// Package lan finds a toss sender on the local network.
//
// The receiver sends a small UDP query to a multicast group, to the
// broadcast addresses of its networks and to the IPv6 link-local multicast
// group of each interface. A sender with the same meeting ID answers, by
// unicast, with the TCP port it listens on. Nothing secret is in these
// packets: the meeting ID only says which transfer to look for, and the
// connection that follows is authenticated by the full code.
//
//	query: "toss1?" | lanID (16) | nonce (16)
//	reply: "toss1!" | lanID (16) | nonce (16) | TCP port (2, big endian)
//
// lanID = SHA-256("toss lan v1" || meetingID)[:16].
package lan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DefaultPort is the UDP port used for discovery (unassigned by IANA).
const DefaultPort = 47923

var (
	// Group4 is the IPv4 multicast group ("organization-local" scope).
	Group4 = netip.MustParseAddr("239.255.116.115")
	// Group6 is the IPv6 link-local multicast group ("toss" in hex).
	Group6 = netip.MustParseAddr("ff02::746f:7373")
)

const (
	queryMagic = "toss1?"
	replyMagic = "toss1!"
	idLen      = 16
	nonceLen   = 16
	queryLen   = len(queryMagic) + idLen + nonceLen
	replyLen   = len(replyMagic) + idLen + nonceLen + 2
)

// ID returns the discovery ID for a meeting ID.
func ID(meetingID string) [idLen]byte {
	sum := sha256.Sum256([]byte("toss lan v1" + meetingID))
	var id [idLen]byte
	copy(id[:], sum[:])
	return id
}

// Responder answers discovery queries for one transfer.
type Responder struct {
	conns []*net.UDPConn
	wg    sync.WaitGroup
}

// ListenOptions configures Listen.
type ListenOptions struct {
	Port int // discovery port; 0 means DefaultPort
	// LoopbackOnly answers only queries from this machine and joins no
	// multicast groups (tests).
	LoopbackOnly bool
}

// Listen starts answering queries for meetingID on the UDP discovery port,
// pointing receivers to tcpPort. Only queries from the local networks are
// answered. It fails only if no socket at all could be opened.
func Listen(meetingID string, tcpPort int, opts ListenOptions) (*Responder, error) {
	discPort := opts.Port
	if discPort == 0 {
		discPort = DefaultPort
	}
	r := &Responder{}
	var errs []error
	join := func(network string, ifi *net.Interface, group netip.Addr) {
		c, err := net.ListenMulticastUDP(network, ifi, net.UDPAddrFromAddrPort(netip.AddrPortFrom(group, uint16(discPort))))
		if err != nil {
			errs = append(errs, err)
			return
		}
		r.conns = append(r.conns, c)
	}
	if !opts.LoopbackOnly {
		ifaces, _ := net.Interfaces()
		for i := range ifaces {
			ifi := &ifaces[i]
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
				continue
			}
			join("udp4", ifi, Group4)
			join("udp6", ifi, Group6)
		}
	}
	if len(r.conns) == 0 {
		// No multicast-capable interface (or loopback only): still answer
		// broadcast and unicast queries.
		ip4, ip6 := net.IPv4zero, net.IPv6unspecified
		if opts.LoopbackOnly {
			ip4, ip6 = net.IPv4(127, 0, 0, 1), net.IPv6loopback
		}
		if c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip4, Port: discPort}); err == nil {
			r.conns = append(r.conns, c)
		} else {
			errs = append(errs, err)
		}
		if c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: ip6, Port: discPort}); err == nil {
			r.conns = append(r.conns, c)
		}
	}
	if len(r.conns) == 0 {
		return nil, errors.Join(errs...)
	}

	id := ID(meetingID)
	reply := make([]byte, replyLen)
	copy(reply, replyMagic)
	copy(reply[len(replyMagic):], id[:])
	binary.BigEndian.PutUint16(reply[replyLen-2:], uint16(tcpPort))

	// The same query reaches us over several sockets and paths; answer
	// each (nonce, source) once.
	var mu sync.Mutex
	seen := map[string]bool{}
	for _, c := range r.conns {
		r.wg.Go(func() {
			buf := make([]byte, 1500)
			for {
				n, src, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				q := buf[:n]
				if n != queryLen || !bytes.HasPrefix(q, []byte(queryMagic)) || !bytes.Equal(q[len(queryMagic):len(queryMagic)+idLen], id[:]) {
					continue
				}
				if !onLink(src.Addr()) {
					continue // not from a local network: don't confirm anything
				}
				nonce := q[len(queryMagic)+idLen:]
				key := string(nonce) + src.Addr().String()
				mu.Lock()
				dup := seen[key]
				if !dup {
					if len(seen) > 4096 {
						clear(seen)
					}
					seen[key] = true
				}
				mu.Unlock()
				if dup {
					continue
				}
				out := bytes.Clone(reply)
				copy(out[len(replyMagic)+idLen:], nonce)
				c.WriteToUDPAddrPort(out, src)
			}
		})
	}
	return r, nil
}

// Close stops answering queries.
func (r *Responder) Close() {
	for _, c := range r.conns {
		c.Close()
	}
	r.wg.Wait()
}

// MaxCandidates bounds how many different sender addresses Find reports,
// so that a flood of fake replies can't make the receiver open connections
// everywhere.
const MaxCandidates = 16

// FindOptions configures Find.
type FindOptions struct {
	Port     int              // discovery port; 0 means DefaultPort
	Interval time.Duration    // time between query rounds; 0 means 1s
	Targets  []netip.AddrPort // where to send queries; nil means automatic
}

// Find queries the local network for a sender with the given meeting ID
// until ctx is done, sending each sender address found (once) on the
// returned channel. The channel is closed when ctx is done.
func Find(ctx context.Context, meetingID string, opts FindOptions) (<-chan netip.AddrPort, error) {
	if opts.Port == 0 {
		opts.Port = DefaultPort
	}
	if opts.Interval == 0 {
		opts.Interval = time.Second
	}
	targets := opts.Targets
	if targets == nil {
		targets = autoTargets(opts.Port)
	}

	var conn4, conn6 *net.UDPConn
	var conns []*net.UDPConn
	if c, err := net.ListenUDP("udp4", nil); err == nil {
		conn4 = c
		conns = append(conns, c)
	}
	if c, err := net.ListenUDP("udp6", nil); err == nil {
		conn6 = c
		conns = append(conns, c)
	}
	if len(conns) == 0 {
		return nil, errors.New("can't open a UDP socket for discovery")
	}

	id := ID(meetingID)
	query := make([]byte, 0, queryLen)
	query = append(query, queryMagic...)
	query = append(query, id[:]...)
	nonce := make([]byte, nonceLen)
	rand.Read(nonce)
	query = append(query, nonce...)

	out := make(chan netip.AddrPort)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := map[netip.AddrPort]bool{}
	for _, c := range conns {
		wg.Go(func() {
			buf := make([]byte, 1500)
			for {
				n, src, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				r := buf[:n]
				if n != replyLen || !bytes.HasPrefix(r, []byte(replyMagic)) ||
					!bytes.Equal(r[len(replyMagic):len(replyMagic)+idLen], id[:]) ||
					!bytes.Equal(r[len(replyMagic)+idLen:replyLen-2], nonce) {
					continue
				}
				port := binary.BigEndian.Uint16(r[replyLen-2:])
				if port == 0 || !onLink(src.Addr()) {
					continue
				}
				ap := netip.AddrPortFrom(src.Addr().Unmap(), port)
				mu.Lock()
				dup := found[ap]
				full := len(found) >= MaxCandidates
				if !dup && !full {
					found[ap] = true
				}
				mu.Unlock()
				if dup || full {
					continue
				}
				select {
				case out <- ap:
				case <-ctx.Done():
					return
				}
			}
		})
	}
	wg.Go(func() {
		t := time.NewTicker(opts.Interval)
		defer t.Stop()
		for {
			for _, dst := range targets {
				// Errors are expected (no route, no IPv6...); the
				// other targets may still work.
				if dst.Addr().Is4() && conn4 != nil {
					conn4.WriteToUDPAddrPort(query, dst)
				} else if dst.Addr().Is6() && conn6 != nil {
					conn6.WriteToUDPAddrPort(query, dst)
				}
			}
			select {
			case <-t.C:
			case <-ctx.Done():
				for _, c := range conns {
					c.Close()
				}
				return
			}
		}
	})
	go func() {
		wg.Wait()
		close(out)
	}()
	return out, nil
}

// autoTargets lists where to send queries: the multicast groups, the
// limited and directed broadcast addresses, and loopback (for a sender on
// the same machine).
func autoTargets(port int) []netip.AddrPort {
	p := uint16(port)
	t := []netip.AddrPort{
		netip.AddrPortFrom(Group4, p),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), p),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), p),
		netip.AddrPortFrom(netip.IPv6Loopback(), p),
	}
	ifaces, _ := net.Interfaces()
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		if ifi.Flags&net.FlagMulticast != 0 {
			t = append(t, netip.AddrPortFrom(Group6.WithZone(ifi.Name), p))
		}
		if ifi.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4, mask := ipn.IP.To4(), ipn.Mask
			if ip4 == nil || len(mask) != 4 {
				continue
			}
			if ones, _ := mask.Size(); ones > 30 {
				continue
			}
			var b [4]byte
			for i := range b {
				b[i] = ip4[i] | ^mask[i]
			}
			t = append(t, netip.AddrPortFrom(netip.AddrFrom4(b), p))
		}
	}
	return t
}

// Addrs lists this machine's addresses that a receiver could use with the
// code@address form: public IPv4 and global IPv6 addresses first, then
// private ones. Loopback and link-local addresses are left out.
func Addrs() (public, private []netip.Addr) {
	ifaces, _ := net.Interfaces()
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			switch {
			case !ip.IsGlobalUnicast():
			case ip.IsPrivate() || isCGNAT(ip):
				private = append(private, ip)
			default:
				public = append(public, ip)
			}
		}
	}
	return public, private
}

func isCGNAT(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

// onLink reports whether addr is on one of this machine's networks:
// loopback, IPv6 link-local, or inside the prefix of a local interface
// address. Discovery traffic from anywhere else is ignored.
func onLink(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range localPrefixes() {
		if p.Contains(addr.WithZone("")) {
			return true
		}
	}
	return false
}

var prefixCache struct {
	sync.Mutex
	at       time.Time
	prefixes []netip.Prefix
}

// localPrefixes returns the networks of this machine's interface addresses,
// refreshed every few seconds (addresses change, e.g. on DHCP renewal).
func localPrefixes() []netip.Prefix {
	prefixCache.Lock()
	defer prefixCache.Unlock()
	if time.Since(prefixCache.at) < 5*time.Second {
		return prefixCache.prefixes
	}
	var ps []netip.Prefix
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		ones, _ := ipn.Mask.Size()
		if ip.Is4() && ones > 32 {
			ones -= 96
		}
		if p, err := ip.Prefix(ones); err == nil {
			ps = append(ps, p)
		}
	}
	prefixCache.at, prefixCache.prefixes = time.Now(), ps
	return ps
}
