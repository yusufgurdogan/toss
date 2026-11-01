// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package cpace implements the CPace password authenticated key exchange (PAKE)
// instantiated with the ristretto255 group.
//
// PAKEs allow two peers to establish a shared secret key if they agree on a
// password or similar low-entropy value, without letting eavesdropping or
// machine-in-the-middle attackers make multiple attempts at guessing the
// password value. CPace is a balanced PAKE, meaning that both peers need to
// know the password plaintext.
//
// This implementation is loosely based on draft-haase-cpace-01.
//
// Vendored from filippo.io/cpace (commit 24d601e2e469, 2021-01-01). Changes
// from upstream, none of which alter the protocol or its outputs:
//   - golang.org/x/crypto/hkdf replaced by the standard library crypto/hkdf;
//   - golang.org/x/crypto/cryptobyte replaced by explicit uint16 length
//     prefixes (the same encoding);
//   - deprecated ristretto255 methods replaced by their current equivalents.
//
// The upstream transcript test vector still passes (see cpace_test.go).
package cpace

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/gtank/ristretto255"
)

// randReader is the source of randomness. Tests may replace it to check the
// fixed transcript vector; production code never does.
var randReader io.Reader = rand.Reader

// ContextInfo captures the additional connection information that the two peers
// need to agree on for the key to be the same.
type ContextInfo struct {
	idA, idB string
	ad       []byte
}

// NewContextInfo returns a ContextInfo for use with Start or Exchange.
//
// idA represents the identity of the party that uses Start, idB of the party
// that uses Exchange. Identities could be MAC addresses, or IPs and ports.
//
// ad is any additional context the two parties share, and can be nil. Examples
// of values that could be included in ad to protect against protocol downgrade
// and mismatch attacks are the name and transcript of the higher level
// protocol, including any negotiation inputs that led to the use of this PAKE.
func NewContextInfo(idA, idB string, ad []byte) *ContextInfo {
	return &ContextInfo{
		idA: idA, idB: idB, ad: ad,
	}
}

func (c *ContextInfo) validate() error {
	switch {
	case c == nil:
		return errors.New("cpace: ContextInfo can't be nil")
	case len(c.idA) >= 1<<16:
		return errors.New("cpace: idA too long")
	case len(c.idB) >= 1<<16:
		return errors.New("cpace: idB too long")
	case len(c.ad) >= 1<<16:
		return errors.New("cpace: additional data too long")
	default:
		return nil
	}
}

const label = "cpace-r255"

// serialize encodes label, idA, idB and ad, each with a big-endian uint16
// length prefix. validate guarantees every field fits.
func (c *ContextInfo) serialize() []byte {
	var b []byte
	for _, in := range [][]byte{
		[]byte(label), []byte(c.idA), []byte(c.idB), c.ad,
	} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(in)))
		b = append(b, in...)
	}
	return b
}

func secretGenerator(password string, salt []byte, c *ContextInfo) (*ristretto255.Element, error) {
	b, err := hkdf.Key(sha256.New, []byte(password), salt, string(c.serialize()), 64)
	if err != nil {
		return nil, err
	}
	return ristretto255.NewIdentityElement().SetUniformBytes(b)
}

func randomScalar() (*ristretto255.Scalar, error) {
	b := make([]byte, 64)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return nil, err
	}
	return ristretto255.NewScalar().SetUniformBytes(b)
}

// State is a PAKE session in progress, where the initiating party is waiting
// for the peer response.
type State struct {
	transcript []byte
	secret     *ristretto255.Scalar
}

// Start initiates a new PAKE exchange authenticated by password. msgA should be
// sent to the peer, to be processed by Exchange, and s used to process the
// peer's response.
func Start(password string, c *ContextInfo) (msgA []byte, s *State, err error) {
	if err := c.validate(); err != nil {
		return nil, nil, err
	}

	s = &State{}

	salt := make([]byte, 16, 16+32)
	if _, err := io.ReadFull(randReader, salt); err != nil {
		return nil, nil, err
	}

	s.secret, err = randomScalar()
	if err != nil {
		return nil, nil, err
	}

	A, err := secretGenerator(password, salt, c)
	if err != nil {
		return nil, nil, err
	}
	A.ScalarMult(s.secret, A)

	msgA = append(salt, A.Bytes()...)

	s.transcript = make([]byte, 16+32, 16+32+32)
	copy(s.transcript, msgA)

	return msgA, s, nil
}

func deriveKey(peerElement, transcript []byte, secret *ristretto255.Scalar) ([]byte, error) {
	K, err := ristretto255.NewIdentityElement().SetCanonicalBytes(peerElement)
	if err != nil {
		return nil, errors.New("cpace: invalid peer message")
	}
	K.ScalarMult(secret, K)

	// draft-haase-cpace-01 requires checking for the identity element at this
	// stage, but also overloads the identity as the output for invalid peer
	// points (for curves where that check is necessary like P-256) and for
	// degenerate scalar multiplications (for curves with cofactors). In a safe
	// prime order group with an error-checking decode function such as
	// ristretto255, this should not be necessary, as the transcript hash
	// guarantees contributory behavior, but it's cheap so we do it anyway.
	if K.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, errors.New("cpace: invalid peer message")
	}

	h := hmac.New(sha256.New, transcript)
	h.Write(K.Bytes())
	return h.Sum(nil), nil
}

// Finish processes the peer's response, generated by Exchange, and returns the
// shared secret key.
//
// If the two peers agree on the password and ContextInfo, they will derive the
// same key. Note that an error is NOT returned otherwise: the two peers will
// simply derive different keys.
//
// The returned key is suitable to be passed to hkdf.Expand.
func (s *State) Finish(msgB []byte) (key []byte, err error) {
	if len(msgB) != 32 {
		return nil, errors.New("cpace: invalid peer message")
	}

	transcript := append(s.transcript[:16+32:16+32], msgB...)
	return deriveKey(msgB, transcript, s.secret)
}

// Exchange executes a PAKE exchange authenticated by password, processing msgA
// generated by a peer with Start, and returns the shared secret key and msgB.
// msgB should be sent to the peer, to be processed by (*State).Finish.
//
// If the two peers agree on the password and ContextInfo, they will derive the
// same key. Note that an error is NOT returned otherwise: the two peers will
// simply derive different keys.
//
// The returned key is suitable to be passed to hkdf.Expand.
func Exchange(password string, c *ContextInfo, msgA []byte) (msgB, key []byte, err error) {
	if err := c.validate(); err != nil {
		return nil, nil, err
	}

	if len(msgA) != 16+32 {
		return nil, nil, errors.New("cpace: invalid peer message")
	}
	salt := msgA[:16]
	encodedA := msgA[16:]

	secret, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}

	x, err := secretGenerator(password, salt, c)
	if err != nil {
		return nil, nil, err
	}
	x.ScalarMult(secret, x)

	msgB = x.Bytes()

	transcript := make([]byte, 0, 16+32+32)
	transcript = append(transcript, msgA...)
	transcript = append(transcript, msgB...)

	key, err = deriveKey(encodedA, transcript, secret)
	if err != nil {
		return nil, nil, err
	}

	return msgB, key, nil
}
