// Package code generates and parses toss codes.
//
// A code looks like 7392-river-moon-sun: four digits followed by words from
// the EFF short wordlist. It optionally carries the sender's address after an
// "@", for example 7392-river-moon-sun@203.0.113.5:41234.
//
// The digits and the first word form the meeting ID, which is used to find
// the peer and must be treated as public. The whole code is the PAKE
// password. Nothing that is published or sent in the clear may be derived
// from the words after the first one: that would allow offline guessing.
package code

import (
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// NumDigits is the number of digits at the start of every code.
	NumDigits = 4
	// DefaultWords is the number of words in a generated code.
	DefaultWords = 3
	// MinWords and MaxWords bound the number of words a code may have.
	MinWords = 3
	MaxWords = 8
)

//go:embed words.txt
var wordsTxt string

var (
	wordList  = strings.Fields(wordsTxt)
	wordIndex = func() map[string]bool {
		m := make(map[string]bool, len(wordList))
		for _, w := range wordList {
			m[w] = true
		}
		return m
	}()
)

// Words returns the number of words in the wordlist.
func Words() int { return len(wordList) }

// Code is a parsed toss code.
type Code struct {
	Digits string   // exactly NumDigits ASCII digits
	Words  []string // MinWords..MaxWords words from the wordlist
	Addr   string   // optional "host:port" of the sender; empty if none
}

// Generate returns a new random code with DefaultWords words.
func Generate() (Code, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return Code{}, err
	}
	c := Code{Digits: fmt.Sprintf("%04d", n.Int64())}
	for range DefaultWords {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordList))))
		if err != nil {
			return Code{}, err
		}
		c.Words = append(c.Words, wordList[i.Int64()])
	}
	return c, nil
}

// String returns the code without any address, e.g. "7392-river-moon-sun".
// This is also the PAKE password.
func (c Code) String() string {
	return c.Digits + "-" + strings.Join(c.Words, "-")
}

// Password returns the secret shared by both peers: the full code.
func (c Code) Password() string { return c.String() }

// MeetingID returns the public part of the code used to find the peer,
// e.g. "7392-river".
func (c Code) MeetingID() string {
	return c.Digits + "-" + c.Words[0]
}

// WithAddr returns the code followed by "@addr".
func (c Code) WithAddr(addr string) string {
	return c.String() + "@" + addr
}

// Parse parses a code typed by a person. It is lenient about case,
// surrounding space and the separator (spaces, hyphens), and strict about
// everything else, so that typos are reported instead of silently producing
// a different password.
func Parse(s string) (Code, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Code{}, errors.New("empty code")
	}
	var c Code
	if before, after, ok := strings.Cut(s, "@"); ok {
		addr, err := ParseAddr(after)
		if err != nil {
			return Code{}, err
		}
		c.Addr = addr
		s = before
	}
	parts := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return r == '-' || r == ' ' || r == '\t'
	})
	if len(parts) == 0 {
		return Code{}, errors.New("empty code")
	}
	c.Digits = parts[0]
	if len(c.Digits) != NumDigits || strings.Trim(c.Digits, "0123456789") != "" {
		return Code{}, fmt.Errorf("a code starts with %d digits, like 7392-river-moon-sun", NumDigits)
	}
	c.Words = parts[1:]
	if len(c.Words) < MinWords || len(c.Words) > MaxWords {
		return Code{}, fmt.Errorf("a code has %d digits and %d to %d words, like 7392-river-moon-sun", NumDigits, MinWords, MaxWords)
	}
	for _, w := range c.Words {
		if !wordIndex[w] {
			if guess := closest(w); guess != "" {
				return Code{}, fmt.Errorf("%q is not a code word (did you mean %q?)", w, guess)
			}
			return Code{}, fmt.Errorf("%q is not a code word", w)
		}
	}
	return c, nil
}

// ParseAddr validates a "host:port" address given after "@" in a code and
// returns it in canonical form. IPv6 addresses must be in brackets.
func ParseAddr(s string) (string, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("bad address %q after @: want host:port or [ipv6]:port", s)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("bad port in address %q", s)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, uint16(port)).String(), nil
	}
	if !validHostname(host) {
		return "", fmt.Errorf("bad host in address %q", s)
	}
	return net.JoinHostPort(strings.ToLower(host), portStr), nil
}

func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// closest returns the wordlist entry within edit distance 2 of w, or "" if
// there is none or more than one is equally close.
func closest(w string) string {
	if len(w) > 16 {
		return ""
	}
	best, bestDist, tie := "", 3, false
	for _, cand := range wordList {
		d := editDistance(w, cand)
		switch {
		case d < bestDist:
			best, bestDist, tie = cand, d, false
		case d == bestDist:
			tie = true
		}
	}
	if tie {
		return ""
	}
	return best
}

// editDistance is the Damerau-Levenshtein (optimal string alignment) distance.
func editDistance(a, b string) int {
	prev2 := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(b)]
}
