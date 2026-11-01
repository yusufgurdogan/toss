// Package xfer implements the toss transfer protocol, which runs inside the
// encrypted channel set up by package secure.
//
// Every message is a frame: a 1-byte type, a 4-byte big-endian payload
// length and the payload. Control messages carry JSON; file data is raw.
//
//	sender                               receiver
//	Offer   {files, dirs}          ->
//	                               <-    Accept {ok, check: [{i, n}]}
//	Plan    {hashes}               ->          (SHA-256 of the first n bytes
//	                                            of each checked file)
//	                               <-    Start {from: [{i, n}], skip: [i]}
//	Data... FileEnd {sha256}       ->          (per file, in offer order,
//	  ...                                       except skipped files)
//	                               <-    Done
//
// Either side may send Error at any time and then stop.
//
// Resume works without the receiver ever revealing anything about its own
// files beyond their sizes: the receiver says how many bytes it already has
// (a partial download, or an existing file of the same size), the sender
// answers with the hash of its own first n bytes, and the receiver compares
// locally. A mismatch means starting that file from scratch, or, for an
// existing file and without --overwrite, a conflict.
package xfer

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// Frame types.
const (
	frameOffer   byte = 1
	frameAccept  byte = 2
	framePlan    byte = 3
	frameStart   byte = 4
	frameData    byte = 5
	frameFileEnd byte = 6
	frameDone    byte = 7
	frameError   byte = 8
)

const (
	headerLen  = 5
	maxControl = 64 << 20  // largest JSON message (an offer of ~500k files)
	dataChunk  = 1 << 20   // payload size of Data frames we send
	maxData    = dataChunk // largest Data payload we accept
	maxError   = 4096

	// Limits on what a peer may ask us to create.
	MaxFiles     = 1_000_000
	MaxPathLen   = 4096
	MaxNameLen   = 255
	MaxPathDepth = 128

	// PartSuffix marks partially received files kept for resuming.
	PartSuffix = ".toss-part"
)

// File describes one regular file in an offer.
type File struct {
	Path  string `json:"path"`            // slash-separated, relative
	Size  int64  `json:"size"`            // bytes
	Exec  bool   `json:"exec,omitempty"`  // executable bit
	MTime int64  `json:"mtime,omitempty"` // Unix nanoseconds, 0 = unknown
}

// Offer is what the sender proposes to send.
type Offer struct {
	Files []File   `json:"files"`
	Dirs  []string `json:"dirs,omitempty"` // directories to create (may be empty)
}

// Check asks the sender for the hash of the first N bytes of file I.
type Check struct {
	I int   `json:"i"`
	N int64 `json:"n"`
}

// Accept is the receiver's answer to an offer.
type Accept struct {
	OK     bool    `json:"ok"`
	Reason string  `json:"reason,omitempty"`
	Check  []Check `json:"check,omitempty"`
}

// Plan carries the sender's SHA-256 of the first N bytes of each checked
// file, in the order of Accept.Check. A nil entry means the sender's file is
// now shorter than N bytes.
type Plan struct {
	Hashes [][]byte `json:"hashes"`
}

// Start tells the sender where to begin each file. Files not mentioned start
// at byte 0; files in Skip are not sent at all.
type Start struct {
	From []Check `json:"from,omitempty"`
	Skip []int   `json:"skip,omitempty"`
}

var (
	// ErrReceiverGone and ErrSenderGone mean the connection to the other
	// side was lost in the middle of the transfer.
	ErrReceiverGone = errors.New("the receiver disconnected")
	ErrSenderGone   = errors.New("the sender disconnected")
)

// connLost reports whether err means the connection went away.
func connLost(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNABORTED)
}

// PeerError is an error message received from the other side.
type PeerError struct{ Msg string }

func (e *PeerError) Error() string { return "the other side reported: " + e.Msg }

// ProtocolError means the peer broke the protocol.
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string { return "protocol error: " + e.Msg }

func protoErr(format string, args ...any) error {
	return &ProtocolError{fmt.Sprintf(format, args...)}
}

// frameReader reads frames; the returned payload is valid until the next call.
type frameReader struct {
	r   *bufio.Reader
	buf []byte
}

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{r: bufio.NewReaderSize(r, 256<<10)}
}

func (fr *frameReader) next() (byte, []byte, error) {
	var h [headerLen]byte
	if _, err := io.ReadFull(fr.r, h[:]); err != nil {
		return 0, nil, err
	}
	typ, n := h[0], binary.BigEndian.Uint32(h[1:])
	var limit uint32
	switch typ {
	case frameOffer, frameAccept, framePlan, frameStart:
		limit = maxControl
	case frameData:
		limit = maxData
	case frameFileEnd:
		limit = sha256.Size
	case frameDone:
		limit = 0
	case frameError:
		limit = maxError
	default:
		return 0, nil, protoErr("unknown frame type %d", typ)
	}
	if n > limit {
		return 0, nil, protoErr("frame type %d too large (%d bytes)", typ, n)
	}
	if cap(fr.buf) < int(n) {
		fr.buf = make([]byte, n)
	}
	p := fr.buf[:n]
	if _, err := io.ReadFull(fr.r, p); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	if typ == frameError {
		return 0, nil, &PeerError{Msg: sanitize(string(p))}
	}
	return typ, p, nil
}

// expect reads the next frame and requires it to be of type want. JSON
// payloads are decoded into v when v is not nil.
func (fr *frameReader) expect(want byte, v any) ([]byte, error) {
	typ, p, err := fr.next()
	if err != nil {
		return nil, err
	}
	if typ != want {
		return nil, protoErr("got frame type %d, want %d", typ, want)
	}
	if v != nil {
		if err := json.Unmarshal(p, v); err != nil {
			return nil, protoErr("bad message: %v", err)
		}
	}
	return p, nil
}

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	b := make([]byte, headerLen+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	copy(b[headerLen:], payload)
	_, err := w.Write(b)
	return err
}

func writeJSON(w io.Writer, typ byte, v any) error {
	p, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(p) > maxControl {
		return fmt.Errorf("message too large (%d bytes); send fewer files at once", len(p))
	}
	return writeFrame(w, typ, p)
}

func writeError(w io.Writer, msg string) error {
	if len(msg) > maxError {
		msg = msg[:maxError]
	}
	return writeFrame(w, frameError, []byte(msg))
}

// maxMessage bounds how much of a message from the peer we print.
const maxMessage = 300

// sanitize makes a message from the peer safe and reasonably short to print
// on a terminal.
func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "\ufffd")
	s = strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return '\ufffd'
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > maxMessage {
		s = string([]rune(s)[:maxMessage]) + "..."
	}
	return s
}

// unsafeRune reports runes that could manipulate a terminal or disguise a
// name: anything that isn't visible (control and format characters such as
// bidirectional overrides and zero-width characters, line and paragraph
// separators, private-use and unassigned code points) plus a few letters
// that render as blank. Ordinary spaces are fine.
func unsafeRune(r rune) bool {
	if r == ' ' {
		return false
	}
	if !unicode.IsGraphic(r) {
		return true
	}
	switch r {
	case 0x115f, 0x1160, 0x3164, 0xffa0, // Hangul fillers
		0x2800, // braille blank
		0x034f: // combining grapheme joiner
		return true
	}
	return false
}

// ValidatePath checks that p is a safe relative path to create on this
// system: slash-separated, clean, inside the destination, and free of
// characters that could confuse a terminal or the file system.
func ValidatePath(p string) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case len(p) > MaxPathLen:
		return errors.New("path too long")
	case !utf8.ValidString(p):
		return errors.New("path is not valid UTF-8")
	case strings.ContainsRune(p, '\\'):
		return errors.New(`path contains "\"`)
	case path.IsAbs(p) || path.Clean(p) != p:
		return errors.New("path is not a clean relative path")
	}
	for _, r := range p {
		if unsafeRune(r) {
			return fmt.Errorf("path contains control character %U", r)
		}
		if runtime.GOOS == "windows" && strings.ContainsRune(`<>:"|?*`, r) {
			return fmt.Errorf("path contains %q, which Windows does not allow", r)
		}
	}
	parts := strings.Split(p, "/")
	if len(parts) > MaxPathDepth {
		return errors.New("path too deep")
	}
	for _, part := range parts {
		switch {
		case part == "" || part == "." || part == "..":
			return errors.New("path is not a clean relative path")
		case len(part) > MaxNameLen:
			return errors.New("file name too long")
		case runtime.GOOS == "windows" && strings.TrimRight(part, ". ") != part:
			return errors.New("name ends with a dot or space, which Windows does not allow")
		}
	}
	if !filepath.IsLocal(filepath.FromSlash(p)) {
		return errors.New("path is not local (reserved name?)")
	}
	return nil
}

// caseInsensitiveFS reports whether file names on this OS are usually case
// insensitive, so that "A" and "a" in one offer would collide.
func caseInsensitiveFS() bool {
	switch runtime.GOOS {
	case "windows", "darwin", "ios":
		return true
	}
	return false
}

func foldKey(p string) string {
	if caseInsensitiveFS() {
		return caseFold(p)
	}
	return p
}

// caseFold maps p to a form where names that a case-insensitive file
// system treats as equal are equal, e.g. "ſ" and "S", or "K" (Kelvin) and "k".
func caseFold(p string) string {
	return strings.ToUpper(strings.ToLower(p))
}

// IsPartName reports whether p ends in PartSuffix in any letter case, as a
// case-insensitive file system would see it.
func IsPartName(p string) bool {
	return strings.HasSuffix(caseFold(p), caseFold(PartSuffix))
}

// validateOffer checks everything about an offer that does not depend on the
// receiver's file system and returns the total size.
func validateOffer(o *Offer) (total int64, err error) {
	if len(o.Files) > MaxFiles || len(o.Dirs) > MaxFiles {
		return 0, fmt.Errorf("too many files (limit %d)", MaxFiles)
	}
	files := make(map[string]bool, len(o.Files))
	for _, f := range o.Files {
		if err := ValidatePath(f.Path); err != nil {
			return 0, fmt.Errorf("unsafe file name %q: %w", sanitize(f.Path), err)
		}
		if IsPartName(f.Path) {
			return 0, fmt.Errorf("file name %q ends in %s, which toss reserves for partial files", f.Path, PartSuffix)
		}
		if f.Size < 0 {
			return 0, fmt.Errorf("negative size for %q", f.Path)
		}
		if total > (1<<63-1)-f.Size {
			return 0, errors.New("total size overflows")
		}
		total += f.Size
		k := foldKey(f.Path)
		if files[k] {
			if caseInsensitiveFS() {
				return 0, fmt.Errorf("the offer contains %q twice (names that differ only in case collide on this system)", f.Path)
			}
			return 0, fmt.Errorf("the offer contains %q twice", f.Path)
		}
		files[k] = true
	}
	// A file must not also be a directory: neither a parent of another
	// file nor an entry in Dirs.
	for _, f := range o.Files {
		for dir := path.Dir(f.Path); dir != "."; dir = path.Dir(dir) {
			if files[foldKey(dir)] {
				return 0, fmt.Errorf("%q is both a file and a folder in the offer", dir)
			}
		}
	}
	for _, d := range o.Dirs {
		if err := ValidatePath(d); err != nil {
			return 0, fmt.Errorf("unsafe folder name %q: %w", sanitize(d), err)
		}
		for dir := d; dir != "."; dir = path.Dir(dir) {
			if files[foldKey(dir)] {
				return 0, fmt.Errorf("%q is both a file and a folder in the offer", dir)
			}
		}
	}
	return total, nil
}
