package dht

import (
	"net"
	"net/netip"
	"sync"
)

// FakeNode is a minimal DHT node for tests. It answers get_peers with
// stored peers, a token and the other nodes it knows, and stores
// announce_peer, like a real node, but only on the address it is given
// (loopback in tests) and with no routing table.
type FakeNode struct {
	ID ID

	conn  *net.UDPConn
	v6    bool
	mu    sync.Mutex
	peers map[ID]map[netip.AddrPort]bool
	known []Node
	wg    sync.WaitGroup
}

// NewFakeNode starts a fake node listening on addr ("127.0.0.1:0").
func NewFakeNode(addr string) (*FakeNode, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if ap.Addr().Is6() {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return nil, err
	}
	f := &FakeNode{conn: conn, v6: ap.Addr().Is6(), peers: map[ID]map[netip.AddrPort]bool{}}
	f.ID = HashOf(conn.LocalAddr().String())
	f.wg.Go(f.serve)
	return f, nil
}

// Addr is the node's address.
func (f *FakeNode) Addr() netip.AddrPort {
	return f.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Know adds nodes this node tells others about.
func (f *FakeNode) Know(nodes ...*FakeNode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range nodes {
		if n != f {
			f.known = append(f.known, Node{ID: n.ID, Addr: n.Addr()})
		}
	}
}

// Peers returns what has been announced for target.
func (f *FakeNode) Peers(target ID) []netip.AddrPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []netip.AddrPort
	for a := range f.peers[target] {
		out = append(out, a)
	}
	return out
}

// Close stops the node.
func (f *FakeNode) Close() {
	f.conn.Close()
	f.wg.Wait()
}

func (f *FakeNode) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		v, err := decode(buf[:n])
		if err != nil {
			continue
		}
		msg, _ := v.(map[string]any)
		if y, _ := msg["y"].(string); y != "q" {
			continue
		}
		q, _ := msg["q"].(string)
		args, _ := msg["a"].(map[string]any)
		r := map[string]any{"id": string(f.ID[:])}
		switch q {
		case "ping":
		case "get_peers", "find_node":
			ih, _ := args["info_hash"].(string)
			var target ID
			copy(target[:], ih)
			f.mu.Lock()
			var vals []any
			for a := range f.peers[target] {
				vals = append(vals, compactAddr(a))
			}
			var nodes []byte
			for _, kn := range f.known {
				nodes = append(nodes, kn.ID[:]...)
				nodes = append(nodes, compactAddr(kn.Addr)...)
			}
			f.mu.Unlock()
			if len(vals) > 0 {
				r["values"] = vals
			}
			if f.v6 {
				r["nodes6"] = string(nodes)
			} else {
				r["nodes"] = string(nodes)
			}
			r["token"] = "tok"
		case "announce_peer":
			ih, _ := args["info_hash"].(string)
			tok, _ := args["token"].(string)
			if len(ih) != 20 || tok != "tok" {
				f.reply(from, msg["t"], map[string]any{"y": "e", "e": []any{203, "bad token"}})
				continue
			}
			port, _ := args["port"].(int64)
			if implied, _ := args["implied_port"].(int64); implied == 1 {
				port = int64(from.Port())
			}
			var target ID
			copy(target[:], ih)
			f.mu.Lock()
			if f.peers[target] == nil {
				f.peers[target] = map[netip.AddrPort]bool{}
			}
			f.peers[target][netip.AddrPortFrom(from.Addr(), uint16(port))] = true
			f.mu.Unlock()
		default:
			f.reply(from, msg["t"], map[string]any{"y": "e", "e": []any{204, "method unknown"}})
			continue
		}
		f.reply(from, msg["t"], map[string]any{"y": "r", "r": r})
	}
}

func (f *FakeNode) reply(to netip.AddrPort, t any, m map[string]any) {
	m["t"] = t
	m["ip"] = compactAddr(to) // BEP 42: tell the querier its address
	b, err := encode(m)
	if err != nil {
		return
	}
	f.conn.WriteToUDPAddrPort(b, to)
}
