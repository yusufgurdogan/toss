package code

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestWordlist(t *testing.T) {
	if Words() != 1296 {
		t.Fatalf("wordlist has %d words, want 1296", Words())
	}
	// Pin the exact list: changing it would silently change which codes are
	// valid and make old and new versions disagree.
	sum := sha256.Sum256([]byte(strings.Join(wordList, "\n") + "\n"))
	if got := hex.EncodeToString(sum[:]); got != "9b57701391f9f867eac0d489f711c7f4a4d88cfd44d554ce7e8f746cf28eaae6" {
		t.Errorf("wordlist changed: hash %s", got)
	}
	seen := map[string]bool{}
	for _, w := range wordList {
		if seen[w] {
			t.Errorf("duplicate word %q", w)
		}
		seen[w] = true
		if strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") != "" {
			t.Errorf("word %q has characters other than a-z", w)
		}
	}
}

func TestGenerateParseRoundTrip(t *testing.T) {
	for range 1000 {
		c, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Words) != DefaultWords || len(c.Digits) != NumDigits {
			t.Fatalf("bad generated code %q", c)
		}
		p, err := Parse(c.String())
		if err != nil {
			t.Fatalf("Parse(%q): %v", c, err)
		}
		if p.String() != c.String() || p.Addr != "" {
			t.Fatalf("round trip %q -> %q", c, p)
		}
		if !strings.HasPrefix(c.String(), c.MeetingID()+"-") {
			t.Fatalf("meeting ID %q is not a prefix of %q", c.MeetingID(), c)
		}
	}
}

func TestParse(t *testing.T) {
	ok := []struct{ in, code, meeting, addr string }{
		{"7392-acid-acorn-acre", "7392-acid-acorn-acre", "7392-acid", ""},
		{"  0042-ACID-Acorn-acre \n", "0042-acid-acorn-acre", "0042-acid", ""},
		{"7392 acid acorn acre", "7392-acid-acorn-acre", "7392-acid", ""},
		{"7392--acid-acorn-acre", "7392-acid-acorn-acre", "7392-acid", ""},
		{"7392-acid-acorn-acre-yoyo-yolk", "7392-acid-acorn-acre-yoyo-yolk", "7392-acid", ""},
		{"7392-acid-acorn-acre@203.0.113.5:41234", "7392-acid-acorn-acre", "7392-acid", "203.0.113.5:41234"},
		{"7392-acid-acorn-acre@[2001:DB8::1]:9", "7392-acid-acorn-acre", "7392-acid", "[2001:db8::1]:9"},
		{"7392-acid-acorn-acre@[fe80::1%eth0]:9", "7392-acid-acorn-acre", "7392-acid", "[fe80::1%eth0]:9"},
		{"7392-acid-acorn-acre@Example.COM:80", "7392-acid-acorn-acre", "7392-acid", "example.com:80"},
	}
	for _, tt := range ok {
		c, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.in, err)
			continue
		}
		if c.String() != tt.code || c.Password() != tt.code || c.MeetingID() != tt.meeting || c.Addr != tt.addr {
			t.Errorf("Parse(%q) = %q meeting %q addr %q", tt.in, c, c.MeetingID(), c.Addr)
		}
	}

	bad := []struct{ in, errPart string }{
		{"", "empty"},
		{"   ", "empty"},
		{"7392", "words"},
		{"7392-acid-acorn", "words"},
		{"739-acid-acorn-acre", "digits"},
		{"73921-acid-acorn-acre", "digits"},
		{"73a2-acid-acorn-acre", "digits"},
		{"acid-7392-acorn-acre", "digits"},
		{"7392-acid-acorn-acre-acid-acid-acid-acid-acid-acid", "words"},
		{"7392-acid-tuilp-acre", `did you mean "tulip"`},
		{"7392-acid-zebar-acre", `did you mean "zebra"`},
		{"7392-acid-acorn-xxxxxxxxx", "not a code word"},
		{"7392-acid-acorn-acre@", "address"},
		{"7392-acid-acorn-acre@1.2.3.4", "address"},
		{"7392-acid-acorn-acre@1.2.3.4:0", "port"},
		{"7392-acid-acorn-acre@1.2.3.4:65536", "port"},
		{"7392-acid-acorn-acre@2001:db8::1:80", "address"},
		{"7392-acid-acorn-acre@bad_host:80", "host"},
		{"7392-acid-acorn-acre@-bad.com:80", "host"},
	}
	for _, tt := range bad {
		_, err := Parse(tt.in)
		if err == nil || !strings.Contains(err.Error(), tt.errPart) {
			t.Errorf("Parse(%q) error = %v, want one containing %q", tt.in, err, tt.errPart)
		}
	}
}

func TestEditDistance(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		d    int
	}{
		{"", "", 0}, {"a", "", 1}, {"", "ab", 2}, {"acorn", "acron", 1},
		{"river", "rivre", 1}, {"kitten", "sitting", 3}, {"same", "same", 0},
	} {
		if got := editDistance(tt.a, tt.b); got != tt.d {
			t.Errorf("editDistance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.d)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("7392-acid-acorn-acre@[::1]:5")
	f.Add("0000 yoyo yolk acid")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := Parse(s)
		if err != nil {
			return
		}
		again, err := Parse(c.String())
		if err != nil || again.String() != c.String() {
			t.Fatalf("canonical form %q of %q does not re-parse: %v", c, s, err)
		}
		if c.Addr != "" {
			if _, err := ParseAddr(c.Addr); err != nil {
				t.Fatalf("canonical address %q does not re-parse: %v", c.Addr, err)
			}
		}
	})
}
