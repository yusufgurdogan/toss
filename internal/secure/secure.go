// Package secure turns a raw connection between a toss sender and receiver
// into an authenticated, encrypted channel.
//
// The steps are:
//
//  1. A plain preamble, "TOSS" plus a protocol version byte, so that a peer
//     running a different protocol version gets a clear error.
//  2. A TLS 1.3 handshake. The sender is the server and uses a fresh
//     self-signed Ed25519 certificate; the receiver does not check it.
//  3. A CPace PAKE (ristretto255) run inside TLS, with the full toss code as
//     the password and the TLS exporter as additional data. Binding the PAKE
//     to the exporter means a machine in the middle that terminates TLS on
//     both sides ends up with two different exporters and cannot complete the
//     PAKE without knowing the code.
//  4. Key confirmation: the receiver proves it derived the same key, then the
//     sender does. The sender reveals nothing that could confirm a guess until
//     the receiver has committed to its proof.
//
// A wrong proof is one wrong guess at the code. The sender allows exactly one:
// after that the Server refuses every further attempt (the code is
// "burned"), so an attacker gets a single chance of roughly one in 1.7 million
// to guess the two secret words.
package secure

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/yusufgurdogan/toss/internal/cpace"
)

// ProtocolVersion is the toss wire protocol version. Peers with different
// versions refuse to talk to each other.
const ProtocolVersion = 1

const (
	magic        = "TOSS"
	alpn         = "toss/1"
	exporterName = "EXPORTER-toss-pake-v1"
	idReceiver   = "toss-receiver"
	idSender     = "toss-sender"

	msgALen = 16 + 32
	msgBLen = 32
	macLen  = sha256.Size

	statusWrongCode byte = 0
	statusOK        byte = 1
	statusRefused   byte = 2
)

// DefaultHandshakeTimeout bounds a handshake when the context has no deadline.
const DefaultHandshakeTimeout = 30 * time.Second

var (
	// ErrWrongCode means the two sides used different codes. The sender
	// will not accept any further attempts for this code.
	ErrWrongCode = errors.New("wrong code")
	// ErrRefused means the sender is no longer accepting this code: it was
	// burned by a wrong attempt or already used by another receiver.
	ErrRefused = errors.New("the sender is no longer accepting this code")
	// ErrNotToss means the peer did not speak the toss protocol at all.
	ErrNotToss = errors.New("peer is not a toss program")
	// ErrConfirmLost means the connection broke after the receiver sent its
	// proof of the code. The receiver must treat this like a wrong code: it
	// cannot know whether its proof was checked.
	ErrConfirmLost = errors.New("connection lost while checking the code")
	// ErrLostAfterProof means (on the sender) that the receiver proved it
	// has the code but the connection broke before the handshake ended.
	// The code is spent; no one else will be accepted.
	ErrLostAfterProof = errors.New("the receiver connected with the right code, then the connection broke")
	// ErrPeerFailedConfirm means the sender's proof was wrong, which should
	// be impossible unless someone tampered with the connection.
	ErrPeerFailedConfirm = errors.New("the sender failed to prove it knows the code")
)

// VersionError reports a peer speaking a different protocol version.
type VersionError struct{ Ours, Peer byte }

func (e *VersionError) Error() string {
	newer := "older"
	if e.Peer > e.Ours {
		newer = "newer"
	}
	return fmt.Sprintf("the other side runs a %s toss (protocol %d, this one speaks %d); both sides need the same version", newer, e.Peer, e.Ours)
}

// Server performs sender-side handshakes for one code. It is safe for
// concurrent use and enforces the one-guess rule across all connections.
type Server struct {
	password string
	tlsConf  *tls.Config

	mu     sync.Mutex
	burned bool // a wrong proof was received
	used   bool // a handshake succeeded
}

// NewServer returns a Server for the given password (the full toss code).
func NewServer(password string) (*Server, error) {
	cert, err := selfSignedCert()
	if err != nil {
		return nil, err
	}
	return &Server{
		password: password,
		tlsConf: &tls.Config{
			MinVersion:             tls.VersionTLS13,
			Certificates:           []tls.Certificate{cert},
			NextProtos:             []string{alpn},
			SessionTicketsDisabled: true,
		},
	}, nil
}

// Burned reports whether a wrong code was tried against this server.
func (s *Server) Burned() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.burned
}

// Handshake runs the sender side on conn. On success it returns the TLS
// connection to use for the transfer; the caller owns it. On failure conn is
// closed. ErrWrongCode means this attempt burned the code; ErrRefused means
// the code was already burned or used. Other errors only concern this
// connection.
func (s *Server) Handshake(ctx context.Context, conn net.Conn) (_ *tls.Conn, err error) {
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	stop := applyDeadline(ctx, conn)
	defer stop()

	// The receiver speaks first; answer with our version either way so a
	// mismatched peer can explain the problem to its user.
	peerVer, err := readPreamble(conn)
	if _, werr := conn.Write(preamble()); err == nil && werr != nil {
		err = werr
	}
	if err != nil {
		return nil, err
	}
	if peerVer != ProtocolVersion {
		return nil, &VersionError{Ours: ProtocolVersion, Peer: peerVer}
	}

	tc := tls.Server(conn, s.tlsConf)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	if p := tc.ConnectionState().NegotiatedProtocol; p != alpn {
		return nil, fmt.Errorf("peer negotiated protocol %q, want %q", p, alpn)
	}
	ekm, err := exporter(tc)
	if err != nil {
		return nil, err
	}

	msgA := make([]byte, msgALen)
	if _, err := io.ReadFull(tc, msgA); err != nil {
		return nil, err
	}
	msgB, key, err := cpace.Exchange(s.password, contextInfo(ekm), msgA)
	if err != nil {
		return nil, err
	}
	if _, err := tc.Write(msgB); err != nil {
		return nil, err
	}
	recvKey, sendKey, err := confirmKeys(key)
	if err != nil {
		return nil, err
	}

	peerMAC := make([]byte, macLen)
	if _, err := io.ReadFull(tc, peerMAC); err != nil {
		return nil, err
	}

	// Check the proof under the lock so that at most one wrong guess is
	// ever evaluated, however many connections race here.
	s.mu.Lock()
	switch {
	case s.burned || s.used:
		s.mu.Unlock()
		tc.Write([]byte{statusRefused})
		return nil, ErrRefused
	case !hmac.Equal(peerMAC, confirmMAC(recvKey, idReceiver, msgA, msgB)):
		s.burned = true
		s.mu.Unlock()
		tc.Write([]byte{statusWrongCode})
		return nil, ErrWrongCode
	}
	s.used = true
	s.mu.Unlock()

	reply := append([]byte{statusOK}, confirmMAC(sendKey, idSender, msgA, msgB)...)
	if _, err := tc.Write(reply); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLostAfterProof, err)
	}
	return tc, nil
}

// SentProofError wraps errors that happened after the receiver sent its
// proof of the code. The receiver must not retry with another candidate
// address after one of these: its single guess may have been consumed.
type SentProofError struct{ Err error }

func (e *SentProofError) Error() string { return e.Err.Error() }
func (e *SentProofError) Unwrap() error { return e.Err }

// Client runs the receiver side of the handshake on conn with the given
// password (the full toss code). On success it returns the TLS connection
// to use for the transfer. On failure conn is closed.
//
// Errors wrapped in *SentProofError (including ErrWrongCode, ErrRefused and
// ErrConfirmLost) mean the attempt counted against the code; any other error
// happened before that point, so trying another address is safe.
func Client(ctx context.Context, conn net.Conn, password string) (_ *tls.Conn, err error) {
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	stop := applyDeadline(ctx, conn)
	defer stop()

	if _, err := conn.Write(preamble()); err != nil {
		return nil, err
	}
	peerVer, err := readPreamble(conn)
	if err != nil {
		return nil, err
	}
	if peerVer != ProtocolVersion {
		return nil, &VersionError{Ours: ProtocolVersion, Peer: peerVer}
	}

	tc := tls.Client(conn, &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Authentication comes from the PAKE bound to the TLS exporter,
		// not from certificates: the sender's certificate is ephemeral.
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
		ServerName:         "toss",
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	if p := tc.ConnectionState().NegotiatedProtocol; p != alpn {
		return nil, fmt.Errorf("peer negotiated protocol %q, want %q", p, alpn)
	}
	ekm, err := exporter(tc)
	if err != nil {
		return nil, err
	}

	msgA, state, err := cpace.Start(password, contextInfo(ekm))
	if err != nil {
		return nil, err
	}
	if _, err := tc.Write(msgA); err != nil {
		return nil, err
	}
	msgB := make([]byte, msgBLen)
	if _, err := io.ReadFull(tc, msgB); err != nil {
		return nil, err
	}
	key, err := state.Finish(msgB)
	if err != nil {
		return nil, err
	}
	recvKey, sendKey, err := confirmKeys(key)
	if err != nil {
		return nil, err
	}

	// From here on the attempt counts against the code.
	if _, err := tc.Write(confirmMAC(recvKey, idReceiver, msgA, msgB)); err != nil {
		return nil, &SentProofError{ErrConfirmLost}
	}
	var status [1]byte
	if _, err := io.ReadFull(tc, status[:]); err != nil {
		return nil, &SentProofError{ErrConfirmLost}
	}
	switch status[0] {
	case statusOK:
	case statusWrongCode:
		return nil, &SentProofError{ErrWrongCode}
	case statusRefused:
		return nil, &SentProofError{ErrRefused}
	default:
		return nil, &SentProofError{fmt.Errorf("unexpected handshake status %d", status[0])}
	}
	peerMAC := make([]byte, macLen)
	if _, err := io.ReadFull(tc, peerMAC); err != nil {
		return nil, &SentProofError{ErrConfirmLost}
	}
	if !hmac.Equal(peerMAC, confirmMAC(sendKey, idSender, msgA, msgB)) {
		return nil, &SentProofError{ErrPeerFailedConfirm}
	}
	return tc, nil
}

func preamble() []byte { return append([]byte(magic), ProtocolVersion) }

func readPreamble(r io.Reader) (byte, error) {
	var b [len(magic) + 1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return 0, ErrNotToss
		}
		return 0, err
	}
	if string(b[:len(magic)]) != magic {
		return 0, ErrNotToss
	}
	return b[len(magic)], nil
}

func exporter(tc *tls.Conn) ([]byte, error) {
	cs := tc.ConnectionState()
	if cs.Version != tls.VersionTLS13 {
		return nil, errors.New("tls: not TLS 1.3")
	}
	return cs.ExportKeyingMaterial(exporterName, nil, 32)
}

func contextInfo(ekm []byte) *cpace.ContextInfo {
	ad := append([]byte(alpn), ekm...)
	return cpace.NewContextInfo(idReceiver, idSender, ad)
}

func confirmKeys(key []byte) (recv, send []byte, err error) {
	recv, err = hkdf.Expand(sha256.New, key, "toss/1 confirm receiver", 32)
	if err != nil {
		return nil, nil, err
	}
	send, err = hkdf.Expand(sha256.New, key, "toss/1 confirm sender", 32)
	return recv, send, err
}

func confirmMAC(key []byte, role string, msgA, msgB []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(role))
	h.Write(msgA)
	h.Write(msgB)
	return h.Sum(nil)
}

// applyDeadline makes conn honor ctx (and DefaultHandshakeTimeout when ctx
// has no deadline) until the returned function is called.
func applyDeadline(ctx context.Context, conn net.Conn) func() {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultHandshakeTimeout)
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	return func() {
		stop()
		conn.SetDeadline(time.Time{})
	}
}

func selfSignedCert() (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "toss"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
