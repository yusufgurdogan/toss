// Package qconn adapts a QUIC connection carrying one stream to the
// connection interface the toss transfer protocol uses.
package qconn

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Config is the QUIC configuration for toss connections: generous flow
// control windows so that a single stream can fill fast, long links.
func Config() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		InitialStreamReceiveWindow:     4 << 20,
		MaxStreamReceiveWindow:         64 << 20,
		InitialConnectionReceiveWindow: 6 << 20,
		MaxConnectionReceiveWindow:     96 << 20,
		MaxIncomingStreams:             1,
		MaxIncomingUniStreams:          -1,
	}
}

// closeWait bounds how long Close waits for the peer to finish.
const closeWait = 3 * time.Second

// Conn is one QUIC stream on its own connection, used like a TCP
// connection. Close is graceful: it ends our side of the stream and waits
// briefly for the peer to end its side, so that data still in flight isn't
// thrown away by closing the connection. A Close that happens while a
// Write is blocked (to abort a transfer) closes the connection at once.
type Conn struct {
	conn   *quic.Conn
	stream *quic.Stream
	wmu    sync.Mutex
	once   sync.Once
}

// New wraps a connection and its stream.
func New(conn *quic.Conn, stream *quic.Stream) *Conn {
	return &Conn{conn: conn, stream: stream}
}

func (c *Conn) Read(p []byte) (int, error) { return c.stream.Read(p) }

func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.stream.Write(p)
}

// CloseWrite ends our side of the stream; the peer reads EOF.
func (c *Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.stream.Close()
}

// Close closes the stream and the connection.
func (c *Conn) Close() error {
	c.once.Do(func() {
		if c.wmu.TryLock() {
			c.stream.Close() // send FIN after any data we wrote
			c.wmu.Unlock()
			done := make(chan struct{})
			go func() {
				io.Copy(io.Discard, c.stream) // until the peer's FIN
				close(done)
			}()
			select {
			case <-done:
			case <-c.conn.Context().Done():
			case <-time.After(closeWait):
			}
		}
		c.stream.CancelRead(0)
		c.conn.CloseWithError(0, "")
	})
	return nil
}

// RemoteAddr is the peer's address.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline sets read and write deadlines on the stream.
func (c *Conn) SetDeadline(t time.Time) error { return c.stream.SetDeadline(t) }
