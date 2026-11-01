package dht

import (
	"os"
	"os/signal"
	"strings"
	"testing"
)

// TestServeFakeDHT runs interconnected fake DHT nodes on the addresses in
// TOSS_FAKE_DHT (comma-separated ip:port) until interrupted. It lets the
// NAT simulation run real toss binaries against a private DHT; it is
// skipped otherwise.
func TestServeFakeDHT(t *testing.T) {
	addrs := os.Getenv("TOSS_FAKE_DHT")
	if addrs == "" {
		t.Skip("set TOSS_FAKE_DHT to run fake DHT nodes")
	}
	var nodes []*FakeNode
	for _, a := range strings.Split(addrs, ",") {
		n, err := NewFakeNode(a)
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		n.Know(nodes...)
	}
	t.Logf("fake DHT on %s", addrs)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}
