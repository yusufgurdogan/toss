package dht

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func init() { CacheDir = "" } // tests never touch the real cache

func TestBencodeRoundTrip(t *testing.T) {
	v := map[string]any{"a": map[string]any{"id": "x\x00y", "n": int64(-5)}, "l": []any{"one", int64(2)}, "y": "q"}
	b, err := encode(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "d1:ad2:id3:x\x00y1:ni-5ee1:ll3:onei2ee1:y1:qe" {
		t.Fatalf("encoded %q", b)
	}
	got, err := decode(b)
	if err != nil || !reflect.DeepEqual(got, v) {
		t.Fatalf("decoded %#v, %v", got, err)
	}
	if !IsKRPC(b) {
		t.Error("KRPC message not recognized")
	}
	for _, bad := range []string{"", "i12", "5:abc", "l", "d1:a", "d i1e 1:x e", "i1e1:x", "-1:", "999999999999:x"} {
		if _, err := decode([]byte(bad)); err == nil {
			t.Errorf("decode(%q) succeeded", bad)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:aa1:y1:qe"))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := decode(b)
		if err != nil {
			return
		}
		again, err := encode(v)
		if err != nil {
			t.Fatalf("can't re-encode %#v: %v", v, err)
		}
		if _, err := decode(again); err != nil {
			t.Fatalf("re-encoded value doesn't decode: %v", err)
		}
	})
}

// testNet starts n interconnected fake nodes on loopback.
func testNet(t *testing.T, n int) []*FakeNode {
	t.Helper()
	var nodes []*FakeNode
	for range n {
		f, err := NewFakeNode("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.Close)
		nodes = append(nodes, f)
	}
	for _, f := range nodes {
		f.Know(nodes...)
	}
	return nodes
}

// testClient returns a client on its own loopback socket, bootstrapped
// from the first fake node.
func testClient(t *testing.T, boot *FakeNode) (*Client, *net.UDPConn) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c := New(conn, false)
	c.AllowPrivate = true
	c.Bootstrap = []string{boot.Addr().String()}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			c.Handle(buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return c, conn
}

func TestAnnounceAndFind(t *testing.T) {
	nodes := testNet(t, 12)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := HashOf("toss test")

	a, aconn := testClient(t, nodes[0])
	res, err := a.GetPeers(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Closest) == 0 || len(res.Closest) > k || len(res.Peers) != 0 {
		t.Fatalf("lookup: %d closest, %d peers", len(res.Closest), len(res.Peers))
	}
	if n := a.Announce(ctx, target, res.Closest, 0, true); n != len(res.Closest) {
		t.Fatalf("announced to %d of %d", n, len(res.Closest))
	}

	b, _ := testClient(t, nodes[5])
	res2, err := b.GetPeers(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	want := aconn.LocalAddr().(*net.UDPAddr).AddrPort()
	if len(res2.Peers) != 1 || res2.Peers[0] != want {
		t.Fatalf("found %v, want [%v] (implied port)", res2.Peers, want)
	}
	if got := b.GetPeersFrom(ctx, target, res2.Closest); len(got) != 1 || got[0] != want {
		t.Fatalf("quick re-check found %v", got)
	}
	if ext, n := a.External(); ext != want || n == 0 {
		t.Fatalf("external address %v (%d votes), want %v", ext, n, want)
	}
	if a.ExternalPorts() != 1 {
		t.Fatalf("%d external ports", a.ExternalPorts())
	}
}

func TestPrivateAddressesFilteredByDefault(t *testing.T) {
	c := New(nil, false)
	for _, a := range []string{"127.0.0.1:1", "192.168.1.1:1", "10.0.0.1:1", "100.64.1.1:1", "0.0.0.0:1", "8.8.8.8:0", "[2001:db8::1]:1"} {
		if c.usable(netip.MustParseAddrPort(a)) {
			t.Errorf("%s accepted", a)
		}
	}
	if !c.usable(netip.MustParseAddrPort("8.8.8.8:6881")) {
		t.Error("public address rejected")
	}
	c6 := New(nil, true)
	if c6.usable(netip.MustParseAddrPort("8.8.8.8:6881")) || !c6.usable(netip.MustParseAddrPort("[2606:4700::1]:6881")) {
		t.Error("IPv6 client family filter wrong")
	}
}

func TestCache(t *testing.T) {
	CacheDir = t.TempDir()
	defer func() { CacheDir = "" }()
	c := New(nil, false)
	n := Node{ID: HashOf("x"), Addr: netip.MustParseAddrPort("8.8.8.8:6881")}
	c.remember(n)
	c.Save()
	got := loadCache(false)
	if len(got) != 1 || got[0] != n {
		t.Fatalf("cache %v", got)
	}
}

func TestIgnoresUnsolicited(t *testing.T) {
	c := New(nil, false)
	b, _ := encode(map[string]any{"t": "zz", "y": "r", "r": map[string]any{"id": "x"}})
	if c.Handle(b, netip.MustParseAddrPort("8.8.8.8:1")) {
		t.Error("unsolicited response accepted")
	}
	if c.Handle([]byte("garbage"), netip.MustParseAddrPort("8.8.8.8:1")) {
		t.Error("garbage accepted")
	}
}
