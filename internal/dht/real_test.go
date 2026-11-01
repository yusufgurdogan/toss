package dht

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestRealDHT talks to the public BitTorrent DHT. It only runs when
// TOSS_REAL_DHT=4 or 6 is set; normal test runs stay offline.
func TestRealDHT(t *testing.T) {
	fam := os.Getenv("TOSS_REAL_DHT")
	if fam != "4" && fam != "6" {
		t.Skip("set TOSS_REAL_DHT=4 or 6 to test against the real DHT")
	}
	v6 := fam == "6"
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := New(conn, v6)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			c.Handle(buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
		}
	}()
	var target ID
	rand.Read(target[:])
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	start := time.Now()
	res, err := c.GetPeers(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("lookup: %v, %d closest nodes, %d peers", time.Since(start).Round(time.Millisecond), len(res.Closest), len(res.Peers))
	ext, votes := c.External()
	t.Logf("external address %v (%d votes, %d distinct)", ext, votes, c.ExternalPorts())
	n := c.Announce(ctx, target, res.Closest, 0, true)
	t.Logf("announced to %d nodes", n)

	// A second client (another socket) should now find the first one.
	conn2, _ := net.ListenUDP(network, nil)
	defer conn2.Close()
	c2 := New(conn2, v6)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := conn2.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			c2.Handle(buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
		}
	}()
	start = time.Now()
	res2, err := c2.GetPeers(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("second lookup: %v, peers %v", time.Since(start).Round(time.Millisecond), res2.Peers)
	found := false
	for _, p := range res2.Peers {
		if p == ext {
			found = true
		}
	}
	if !found {
		t.Errorf("announced address %v not found", ext)
	}
}
