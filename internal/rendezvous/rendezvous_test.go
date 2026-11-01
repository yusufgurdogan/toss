package rendezvous

import (
	"context"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/yusufgurdogan/toss/internal/dht"
	"github.com/yusufgurdogan/toss/internal/qconn"
	"github.com/yusufgurdogan/toss/internal/secure"
)

func init() {
	dht.CacheDir = ""
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
}

// fakeDHT starts a small DHT of fake nodes on loopback and returns
// options that point both sides at it.
func fakeDHT(t *testing.T) Options {
	t.Helper()
	var nodes []*dht.FakeNode
	for range 8 {
		n, err := dht.NewFakeNode("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(n.Close)
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		n.Know(nodes...)
	}
	return Options{
		Bind4:        "127.0.0.1:0",
		NoIPv6:       true,
		Bootstrap:    []string{nodes[0].Addr().String()},
		AllowPrivate: true,
		Poll:         200 * time.Millisecond,
	}
}

func TestMeetConnectAndCheckCode(t *testing.T) {
	opts := fakeDHT(t)
	const code = "1234-acid-acorn-acre"
	srv, err := secure.NewServer(code)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	snd, err := StartSender(ctx, "1234-acid", srv.TLSConfig(), qconn.Config(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer snd.Close()
	rcv, err := StartReceiver(ctx, "1234-acid", secure.ClientTLSConfig(), qconn.Config(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer rcv.Close()

	type result struct {
		data string
		err  error
	}
	sent := make(chan result, 1)
	go func() {
		select {
		case c := <-snd.Conns():
			st, err := c.AcceptStream(ctx)
			if err != nil {
				sent <- result{err: err}
				return
			}
			ekm, _ := secure.Exporter(c.ConnectionState().TLS)
			if err := srv.HandshakeStream(st, ekm); err != nil {
				sent <- result{err: err}
				return
			}
			conn := qconn.New(c, st)
			b, err := io.ReadAll(conn)
			conn.Close()
			sent <- result{string(b), err}
		case <-ctx.Done():
			sent <- result{err: ctx.Err()}
		}
	}()

	var c = <-rcv.Conns()
	rcv.Stop()
	st, err := c.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ekm, _ := secure.Exporter(c.ConnectionState().TLS)
	if err := secure.ClientStream(st, ekm, code); err != nil {
		t.Fatal(err)
	}
	conn := qconn.New(c, st)
	conn.Write([]byte("over QUIC, found through the DHT"))
	conn.Close()
	if r := <-sent; r.err != nil || r.data != "over QUIC, found through the DHT" {
		t.Fatalf("sender got %q, %v", r.data, r.err)
	}
}

func TestProbesAreRecognized(t *testing.T) {
	m := newMeeting("1234-acid")
	p := makeProbe(roleSender, m.tag)
	if !isProbe(p) || p[0]&0xc0 != 0 {
		t.Fatal("probe not recognized, or could be taken for QUIC")
	}
	if dht.IsKRPC(p) {
		t.Fatal("probe taken for KRPC")
	}
	if newMeeting("1234-acid").tag != m.tag || newMeeting("1234-acorn").tag == m.tag {
		t.Fatal("tag is not a function of the meeting ID")
	}
	if m.senderKey == m.receiverKey {
		t.Fatal("sender and receiver keys collide")
	}
}

func TestSprayBudget(t *testing.T) {
	var b sprayBudget
	a1, a2, a3 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	if !b.take(a1) || b.take(a1) || !b.take(a2) || b.take(a3) {
		t.Fatal("spray budget doesn't limit targets")
	}
}

func TestPeerPorts(t *testing.T) {
	var pp peerPorts
	if pp.add(netip.MustParseAddrPort("192.0.2.1:1000")) {
		t.Fatal("one port is not a symmetric NAT")
	}
	if !pp.add(netip.MustParseAddrPort("192.0.2.1:2000")) {
		t.Fatal("two ports on one address should look symmetric")
	}
	if pp.add(netip.MustParseAddrPort("192.0.2.1:3000")) {
		t.Fatal("reported twice")
	}
}
