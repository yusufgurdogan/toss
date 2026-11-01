// Package dht is a small client for the BitTorrent mainline DHT (BEP 5),
// with IPv6 support (BEP 32), external address reporting (BEP 42) and
// read-only mode (BEP 43). toss uses it only as a meeting point: each side
// announces itself under a hash of the code's public part and looks up
// the other. The DHT nodes store "this IP and port is interested in this
// hash"; no file data and nothing secret goes through them.
//
// The client doesn't own a socket: it writes through a Sender and is fed
// incoming KRPC packets with Handle, so the same UDP socket (and so the same
// NAT mapping) can be used for the DHT, hole punching and QUIC.
package dht

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Bootstrap lists well-known DHT routers used to join the network when no
// nodes are cached from an earlier run.
var Bootstrap = []string{
	"router.bittorrent.com:6881",
	"router.utorrent.com:6881",
	"dht.transmissionbt.com:6881",
	"dht.libtorrent.org:25401",
	"dht.aelitis.com:6881",
	"router.silotis.us:6881",
}

const (
	alpha        = 8                       // parallel queries during a lookup
	k            = 8                       // nodes to announce to
	queryTimeout = 1500 * time.Millisecond // per query
	slowQuery    = 400 * time.Millisecond  // after this a query no longer blocks others
	maxQueries   = 300                     // per lookup
	maxPeers     = 64                      // per lookup result
)

// ID is a DHT node ID or info hash.
type ID [20]byte

// HashOf returns the info hash toss uses for a string.
func HashOf(s string) ID { return sha1.Sum([]byte(s)) }

// Sender writes UDP packets; *net.UDPConn implements it.
type Sender interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
}

// Node is a DHT node.
type Node struct {
	ID   ID
	Addr netip.AddrPort
}

// Client talks to the DHT over IPv4 or IPv6 (one client per family).
type Client struct {
	conn Sender
	v6   bool
	id   ID
	// AllowPrivate accepts nodes and peers on private and loopback
	// addresses. Only tests set it: on the internet, a node pointing us at
	// local addresses could make us send packets around our own network.
	AllowPrivate bool
	// Bootstrap overrides the bootstrap list (tests).
	Bootstrap []string

	mu      sync.Mutex
	pending map[string]chan map[string]any
	tid     uint32
	votes   map[netip.AddrPort]int // our address as reported by nodes
	good    map[netip.AddrPort]Node
}

// New returns a client that sends through conn. v6 selects the IPv6 DHT.
func New(conn Sender, v6 bool) *Client {
	c := &Client{conn: conn, v6: v6, pending: map[string]chan map[string]any{},
		votes: map[netip.AddrPort]int{}, good: map[netip.AddrPort]Node{}}
	rand.Read(c.id[:])
	return c
}

// Handle processes an incoming packet. It returns false if the packet
// isn't a KRPC response for this client.
func (c *Client) Handle(b []byte, from netip.AddrPort) bool {
	v, err := decode(b)
	if err != nil {
		return false
	}
	msg, ok := v.(map[string]any)
	if !ok {
		return false
	}
	t, _ := msg["t"].(string)
	y, _ := msg["y"].(string)
	if y != "r" && y != "e" {
		return false // we're read-only and don't answer queries
	}
	c.mu.Lock()
	ch := c.pending[t+from.String()]
	delete(c.pending, t+from.String())
	c.mu.Unlock()
	if ch == nil {
		return false
	}
	ch <- msg
	return true
}

// External returns our public address as most DHT nodes report it (BEP
// 42), if any have.
func (c *Client) External() (netip.AddrPort, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best netip.AddrPort
	n := 0
	for a, v := range c.votes {
		if v > n {
			best, n = a, v
		}
	}
	return best, n
}

// ExternalPorts returns how many different external ports nodes have
// reported for us. More than one means the NAT picks a new port per
// destination ("symmetric"), which makes hole punching harder.
func (c *Client) ExternalPorts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.votes)
}

var errTimeout = errors.New("dht: query timed out")

func (c *Client) query(ctx context.Context, to netip.AddrPort, method string, args map[string]any) (map[string]any, error) {
	c.mu.Lock()
	c.tid++
	var tb [4]byte
	binary.BigEndian.PutUint32(tb[:], c.tid)
	t := string(tb[:])
	ch := make(chan map[string]any, 1)
	c.pending[t+to.String()] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, t+to.String())
		c.mu.Unlock()
	}()

	args["id"] = string(c.id[:])
	if c.v6 {
		args["want"] = []string{"n6"}
	} else {
		args["want"] = []string{"n4"}
	}
	pkt, err := encode(map[string]any{"t": t, "y": "q", "q": method, "a": args, "ro": 1})
	if err != nil {
		return nil, err
	}
	if _, err := c.conn.WriteTo(pkt, net.UDPAddrFromAddrPort(to)); err != nil {
		return nil, err
	}
	timer := time.NewTimer(queryTimeout)
	defer timer.Stop()
	select {
	case msg := <-ch:
		if ip, ok := msg["ip"].(string); ok {
			if a, ok := parseCompactAddr(ip); ok {
				c.mu.Lock()
				c.votes[a]++
				c.mu.Unlock()
			}
		}
		if y, _ := msg["y"].(string); y == "e" {
			return nil, fmt.Errorf("dht: error from %v: %v", to, msg["e"])
		}
		r, ok := msg["r"].(map[string]any)
		if !ok {
			return nil, errors.New("dht: malformed response")
		}
		return r, nil
	case <-timer.C:
		return nil, errTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Contact is a node that answered get_peers, with the token needed to
// announce to it.
type Contact struct {
	Node
	Token string
}

// LookupResult is the outcome of a get_peers lookup.
type LookupResult struct {
	Peers   []netip.AddrPort // announced peers found
	Closest []Contact        // the closest nodes that answered, for Announce
}

// GetPeers runs an iterative get_peers lookup for target.
func (c *Client) GetPeers(ctx context.Context, target ID) (*LookupResult, error) {
	return c.getPeers(ctx, target, false)
}

// FindPeers is GetPeers that returns as soon as any peer is found.
func (c *Client) FindPeers(ctx context.Context, target ID) (*LookupResult, error) {
	return c.getPeers(ctx, target, true)
}

func (c *Client) getPeers(ctx context.Context, target ID, earlyStop bool) (*LookupResult, error) {
	type cand struct {
		Node
		known   bool // ID known (bootstrap entries aren't)
		queried bool
		token   string
		ok      bool
	}
	cands := map[netip.AddrPort]*cand{}
	add := func(n Node, known bool) {
		if !c.usable(n.Addr) {
			return
		}
		if _, dup := cands[n.Addr]; !dup && len(cands) < 2000 {
			cands[n.Addr] = &cand{Node: n, known: known}
		}
	}
	for _, n := range c.seeds() {
		add(n, n.ID != ID{})
	}
	for _, a := range c.resolveBootstrap(ctx) {
		add(Node{Addr: a}, false)
	}
	if len(cands) == 0 {
		return nil, errors.New("dht: no nodes to start from (no internet?)")
	}

	dist := func(a *cand) ID {
		if !a.known {
			return ID{} // unknown IDs (bootstrap routers) go first
		}
		return xor(a.ID, target)
	}
	sortCands := func(filter func(*cand) bool) []*cand {
		var list []*cand
		for _, x := range cands {
			if filter(x) {
				list = append(list, x)
			}
		}
		sort.Slice(list, func(i, j int) bool { return less(dist(list[i]), dist(list[j])) })
		return list
	}

	type reply struct {
		c   *cand
		r   map[string]any
		err error
	}
	replies := make(chan reply, alpha*4)
	started := map[*cand]time.Time{} // queries in flight
	queries := 0
	peers := map[netip.AddrPort]bool{}
	res := &LookupResult{}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		// Kademlia termination: stop once nothing closer than the k-th
		// closest node that answered is left to ask.
		answered := sortCands(func(x *cand) bool { return x.ok })
		var bound *ID
		if len(answered) >= k {
			d := dist(answered[k-1])
			bound = &d
		}
		next := sortCands(func(x *cand) bool { return !x.queried && (bound == nil || less(dist(x), *bound)) })
		pendingCloser := 0
		slow := 0
		for x, t0 := range started {
			if time.Since(t0) > slowQuery {
				slow++ // slow queries don't hold up the lookup
			}
			if bound == nil || less(dist(x), *bound) {
				pendingCloser++
			}
		}
		if (len(next) == 0 && pendingCloser == 0) || (queries >= maxQueries && len(started) == 0) {
			break
		}
		if earlyStop && len(peers) > 0 && len(answered) > 0 {
			break
		}
		for _, x := range next {
			if len(started)-slow >= alpha || queries >= maxQueries {
				break
			}
			x.queried = true
			started[x] = time.Now()
			queries++
			go func() {
				r, err := c.query(ctx, x.Addr, "get_peers", map[string]any{"info_hash": string(target[:])})
				replies <- reply{x, r, err}
			}()
		}
		select {
		case rep := <-replies:
			delete(started, rep.c)
			if rep.err != nil {
				continue
			}
			x := rep.c
			if id, ok := rep.r["id"].(string); ok && len(id) == 20 {
				copy(x.ID[:], id)
				x.known = true
				x.ok = true
				c.remember(x.Node)
			}
			x.token, _ = rep.r["token"].(string)
			for _, n := range c.parseNodes(rep.r) {
				add(n, true)
			}
			if vals, ok := rep.r["values"].([]any); ok {
				for _, v := range vals {
					s, _ := v.(string)
					if a, ok := parseCompactAddr(s); ok && c.usable(a) && len(peers) < maxPeers {
						peers[a] = true
					}
				}
			}
		case <-tick.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	for a := range peers {
		res.Peers = append(res.Peers, a)
	}
	for _, x := range sortCands(func(x *cand) bool { return x.ok }) {
		if x.token != "" {
			res.Closest = append(res.Closest, Contact{Node: x.Node, Token: x.token})
			if len(res.Closest) == k {
				break
			}
		}
	}
	return res, nil
}

// GetPeersFrom asks the given nodes directly (a quick re-check after a
// full lookup) and returns the peers they know.
func (c *Client) GetPeersFrom(ctx context.Context, target ID, nodes []Contact) []netip.AddrPort {
	var mu sync.Mutex
	var wg sync.WaitGroup
	found := map[netip.AddrPort]bool{}
	for _, n := range nodes {
		wg.Go(func() {
			r, err := c.query(ctx, n.Addr, "get_peers", map[string]any{"info_hash": string(target[:])})
			if err != nil {
				return
			}
			vals, _ := r["values"].([]any)
			mu.Lock()
			defer mu.Unlock()
			for _, v := range vals {
				s, _ := v.(string)
				if a, ok := parseCompactAddr(s); ok && c.usable(a) && len(found) < maxPeers {
					found[a] = true
				}
			}
		})
	}
	wg.Wait()
	out := make([]netip.AddrPort, 0, len(found))
	for a := range found {
		out = append(out, a)
	}
	return out
}

// Announce tells the given nodes that we're a peer for target. With
// impliedPort the nodes record the source port they see (our NAT's
// mapping); otherwise they record port. It returns how many accepted.
func (c *Client) Announce(ctx context.Context, target ID, nodes []Contact, port int, impliedPort bool) int {
	var mu sync.Mutex
	var wg sync.WaitGroup
	ok := 0
	for _, n := range nodes {
		wg.Go(func() {
			args := map[string]any{"info_hash": string(target[:]), "port": port, "token": n.Token}
			if impliedPort {
				args["implied_port"] = 1
			}
			if _, err := c.query(ctx, n.Addr, "announce_peer", args); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return ok
}

// usable filters addresses we are willing to send packets to.
func (c *Client) usable(a netip.AddrPort) bool {
	ip := a.Addr()
	if !a.IsValid() || a.Port() == 0 || ip.Is4() == c.v6 && !ip.Is4In6() {
		return false
	}
	if c.AllowPrivate {
		return true
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !isSpecial(ip)
}

func isSpecial(ip netip.Addr) bool {
	for _, p := range specialPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var specialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b::/96"),
}

func (c *Client) parseNodes(r map[string]any) []Node {
	key, size := "nodes", 26
	if c.v6 {
		key, size = "nodes6", 38
	}
	s, _ := r[key].(string)
	var out []Node
	for len(s) >= size {
		var n Node
		copy(n.ID[:], s[:20])
		if a, ok := parseCompactAddr(s[20:size]); ok {
			n.Addr = a
			out = append(out, n)
		}
		s = s[size:]
	}
	return out
}

func (c *Client) resolveBootstrap(ctx context.Context) []netip.AddrPort {
	list := c.Bootstrap
	if list == nil {
		list = Bootstrap
	}
	network := "ip4"
	if c.v6 {
		network = "ip6"
	}
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	var out []netip.AddrPort
	for _, hp := range list {
		wg.Go(func() {
			host, portStr, err := net.SplitHostPort(hp)
			if err != nil {
				return
			}
			port, err := netip.ParseAddrPort(net.JoinHostPort("0.0.0.0", portStr))
			if err != nil {
				return
			}
			var ips []netip.Addr
			if ip, err := netip.ParseAddr(host); err == nil {
				ips = []netip.Addr{ip}
			} else {
				ips, _ = net.DefaultResolver.LookupNetIP(rctx, network, host)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, ip := range ips {
				out = append(out, netip.AddrPortFrom(ip.Unmap(), port.Port()))
			}
		})
	}
	wg.Wait()
	return out
}

func (c *Client) remember(n Node) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.good) < 512 {
		c.good[n.Addr] = n
	}
}

// seeds returns nodes known from this session and the on-disk cache.
func (c *Client) seeds() []Node {
	c.mu.Lock()
	out := make([]Node, 0, len(c.good))
	for _, n := range c.good {
		out = append(out, n)
	}
	c.mu.Unlock()
	return append(out, loadCache(c.v6)...)
}

// Save writes the nodes that answered in this session to the on-disk cache,
// so the next run needs the bootstrap routers less.
func (c *Client) Save() {
	c.mu.Lock()
	nodes := make([]Node, 0, len(c.good))
	for _, n := range c.good {
		nodes = append(nodes, n)
	}
	c.mu.Unlock()
	saveCache(c.v6, nodes)
}

func parseCompactAddr(s string) (netip.AddrPort, bool) {
	switch len(s) {
	case 6:
		ip := netip.AddrFrom4([4]byte([]byte(s[:4])))
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16([]byte(s[4:]))), true
	case 18:
		ip := netip.AddrFrom16([16]byte([]byte(s[:16]))).Unmap()
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16([]byte(s[16:]))), true
	}
	return netip.AddrPort{}, false
}

func compactAddr(a netip.AddrPort) string {
	b := a.Addr().AsSlice()
	if a.Addr().Is4() {
		b = a.Addr().Unmap().AsSlice()
	}
	return string(binary.BigEndian.AppendUint16(b, a.Port()))
}

func xor(a, b ID) ID {
	var d ID
	for i := range d {
		d[i] = a[i] ^ b[i]
	}
	return d
}

func less(a, b ID) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
