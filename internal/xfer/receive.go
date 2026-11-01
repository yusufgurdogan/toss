package xfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// ReceiveOptions configures Receive.
type ReceiveOptions struct {
	// Overwrite allows replacing existing files that differ from the
	// incoming ones. Folders are never replaced.
	Overwrite bool
	// Confirm is called after the offer has been checked against the
	// destination; returning false declines. If nil, offers are accepted.
	// It is not called when the offer can't be received (Summary.Problems).
	Confirm func(*Summary) bool
	// Progress, if set, is called as data arrives. It must return quickly.
	Progress func(Progress)
	// Status, if set, is told about slow phases (e.g. checking files).
	Status func(string)
}

// Summary describes an offer as it applies to the destination folder.
type Summary struct {
	Offer Offer
	Total int64 // bytes in the offer

	Partial      int   // partially received files found (resumable)
	PartialBytes int64 // bytes already present in them
	Existing     int   // files already present with the same size; skipped if identical
	ExistingSize int64
	Replace      []string // existing files that will be replaced (Overwrite only)

	// Things to point out before saying yes (see notable.go).
	Sensitive   []string // .ssh, .gnupg or .git folders in the offer
	Executables []string // files marked executable or with a runnable extension

	FreeSpace int64 // bytes free at the destination, -1 if unknown
	Needed    int64 // lower bound of bytes this transfer will add

	// Problems that prevent receiving at all, e.g. existing files without
	// Overwrite. When non-empty the offer is declined automatically.
	Problems []string
}

// ConflictError means the offer could not be received into the
// destination; Problems explains why.
type ConflictError struct{ Problems []string }

func (e *ConflictError) Error() string {
	if len(e.Problems) == 1 {
		return e.Problems[0]
	}
	return fmt.Sprintf("%s (and %d more problems)", e.Problems[0], len(e.Problems)-1)
}

// UnsafeOfferError means the sender offered something that can't be
// received safely (e.g. a path outside the destination) and was refused.
type UnsafeOfferError struct{ Err error }

func (e *UnsafeOfferError) Error() string { return "refused an unsafe offer: " + e.Err.Error() }
func (e *UnsafeOfferError) Unwrap() error { return e.Err }

// ErrDeclined is returned when Confirm declined the offer.
var ErrDeclined = errors.New("declined")

type fileKind int

const (
	kindNew      fileKind = iota // nothing at the destination
	kindPartial                  // a .toss-part file to resume from
	kindExisting                 // a regular file of the same size
	kindReplace                  // an existing file to replace (Overwrite)
)

type localFile struct {
	kind fileKind
	n    int64 // bytes present (partial or existing)
}

// halfCloser is implemented by *tls.Conn and *net.TCPConn.
type halfCloser interface{ CloseWrite() error }

// Receive runs the receiver side of the transfer protocol over conn, which
// must already be secured, writing everything inside root. conn is closed
// when Receive returns. Partially received files are kept for resuming.
func Receive(ctx context.Context, conn io.ReadWriteCloser, root *os.Root, opts ReceiveOptions) (*Result, error) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	r := &receiver{conn: conn, fr: newFrameReader(conn), root: root, opts: opts}
	res, err := r.run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var local *localError
	var perr *ProtocolError
	switch {
	case errors.As(err, &local):
		r.abort(local.peerMsg)
		return nil, local.err
	case errors.As(err, &perr):
		r.abort(perr.Error())
	case err != nil && connLost(err):
		return nil, ErrSenderGone
	}
	return res, err
}

// localError is a failure on our side; peerMsg is what we tell the sender.
type localError struct {
	err     error
	peerMsg string
}

func (e *localError) Error() string { return e.err.Error() }
func (e *localError) Unwrap() error { return e.err }

func fail(peerMsg string, err error) error { return &localError{err: err, peerMsg: peerMsg} }

type receiver struct {
	conn io.ReadWriteCloser
	fr   *frameReader
	root *os.Root
	opts ReceiveOptions
	pool chan *chunk // data buffers for the write pipeline
}

// abort tells the sender why we stop and gives the message a moment to
// arrive before the connection is closed.
func (r *receiver) abort(msg string) {
	if writeError(r.conn, msg) != nil {
		return
	}
	if hc, ok := r.conn.(halfCloser); ok {
		hc.CloseWrite()
	}
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, r.conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (r *receiver) status(s string) {
	if r.opts.Status != nil {
		r.opts.Status(s)
	}
}

func (r *receiver) run() (*Result, error) {
	var offer Offer
	if _, err := r.fr.expect(frameOffer, &offer); err != nil {
		return nil, err
	}
	total, err := validateOffer(&offer)
	if err != nil {
		// Declining tells the sender; no need for an Error frame too.
		writeJSON(r.conn, frameAccept, &Accept{Reason: "the offer is not safe to receive"})
		return nil, &UnsafeOfferError{Err: err}
	}
	files := offer.Files

	local, sum := r.inspect(&offer, total)
	if len(sum.Problems) > 0 {
		// Decline exactly like a person saying no, so the sender can't
		// tell which of its files exist here or how full the disk is.
		writeJSON(r.conn, frameAccept, &Accept{})
		return nil, &ConflictError{Problems: sum.Problems}
	}
	if r.opts.Confirm != nil && !r.opts.Confirm(sum) {
		writeJSON(r.conn, frameAccept, &Accept{})
		return nil, ErrDeclined
	}

	acc := Accept{OK: true}
	for i, lf := range local {
		if (lf.kind == kindPartial || lf.kind == kindExisting) && lf.n > 0 {
			acc.Check = append(acc.Check, Check{I: i, N: lf.n})
		}
	}
	if err := writeJSON(r.conn, frameAccept, &acc); err != nil {
		return nil, err
	}

	// Hash what we have while the sender does the same.
	if len(acc.Check) > 0 {
		r.status(fmt.Sprintf("Checking %d file(s) already here...", len(acc.Check)))
	}
	ours := make([]hash.Hash, len(acc.Check))
	parallel(len(acc.Check), func(k int) {
		c := acc.Check[k]
		name := files[c.I].Path
		if local[c.I].kind == kindPartial {
			name = partName(name)
		}
		if h, err := r.hashLocalPrefix(name, c.N); err == nil {
			ours[k] = h
		}
	})
	var plan Plan
	if _, err := r.fr.expect(framePlan, &plan); err != nil {
		return nil, err
	}
	if len(plan.Hashes) != len(acc.Check) {
		return nil, protoErr("plan has %d hashes for %d checks", len(plan.Hashes), len(acc.Check))
	}

	var start Start
	from := make(map[int]int64)
	resumeHash := make(map[int]hash.Hash)
	skip := make(map[int]bool)
	var problems []string
	for k, c := range acc.Check {
		match := ours[k] != nil && plan.Hashes[k] != nil && bytes.Equal(ours[k].Sum(nil), plan.Hashes[k])
		switch {
		case local[c.I].kind == kindPartial && match:
			start.From = append(start.From, c)
			from[c.I] = c.N
			resumeHash[c.I] = ours[k]
		case local[c.I].kind == kindPartial:
			// Different content: start that file over.
		case match: // kindExisting, identical
			start.Skip = append(start.Skip, c.I)
			skip[c.I] = true
		case r.opts.Overwrite:
			local[c.I].kind = kindReplace
		default:
			problems = append(problems, fmt.Sprintf("%s already exists and is different", files[c.I].Path))
		}
	}
	for i, f := range files {
		if f.Size == 0 && local[i].kind == kindExisting {
			start.Skip = append(start.Skip, i)
			skip[i] = true
		}
	}
	if len(problems) > 0 {
		return nil, fail("files with the same names but different contents already exist on the receiver",
			&ConflictError{Problems: problems})
	}
	if err := writeJSON(r.conn, frameStart, &start); err != nil {
		return nil, err
	}

	res := &Result{Files: len(files)}
	var sessionTotal int64
	for i, f := range files {
		if skip[i] {
			res.Unchanged++
			res.Resumed += f.Size
			continue
		}
		res.Resumed += from[i]
		sessionTotal += f.Size - from[i]
	}
	p := Progress{Total: sessionTotal, Resumed: res.Resumed}
	for i, f := range files {
		if skip[i] {
			continue
		}
		p.File = f.Path
		if err := r.receiveFile(f, from[i], resumeHash[i], &p); err != nil {
			return nil, err
		}
	}
	for _, d := range offer.Dirs {
		if err := r.root.MkdirAll(d, 0o777); err != nil {
			return nil, fail("the receiver could not create a folder", err)
		}
	}
	res.Bytes = p.Done
	if err := writeFrame(r.conn, frameDone, nil); err != nil {
		return nil, err
	}
	return res, nil
}

// inspect compares the offer with the destination folder.
func (r *receiver) inspect(o *Offer, total int64) ([]localFile, *Summary) {
	sum := &Summary{Offer: *o, Total: total, FreeSpace: -1, Sensitive: Sensitive(o), Executables: Executables(o)}
	local := make([]localFile, len(o.Files))
	for i, f := range o.Files {
		st, err := r.root.Lstat(f.Path)
		switch {
		case err == nil && st.IsDir():
			sum.Problems = append(sum.Problems, fmt.Sprintf("%s already exists as a folder", f.Path))
		case err == nil && st.Mode().IsRegular() && st.Size() == f.Size:
			local[i] = localFile{kind: kindExisting, n: f.Size}
			sum.Existing++
			sum.ExistingSize += f.Size
		case err == nil && r.opts.Overwrite:
			local[i] = localFile{kind: kindReplace}
			sum.Replace = append(sum.Replace, f.Path)
		case err == nil:
			sum.Problems = append(sum.Problems, fmt.Sprintf("%s already exists", f.Path))
		case errors.Is(err, fs.ErrNotExist):
			if pst, err := r.root.Lstat(partName(f.Path)); err == nil && pst.Mode().IsRegular() && pst.Size() > 0 && pst.Size() <= f.Size {
				local[i] = localFile{kind: kindPartial, n: pst.Size()}
				sum.Partial++
				sum.PartialBytes += pst.Size()
			}
		default:
			sum.Problems = append(sum.Problems, fmt.Sprintf("can't write %s: %v", f.Path, cleanErr(err)))
		}
	}
	for _, d := range o.Dirs {
		st, err := r.root.Stat(d)
		switch {
		case err == nil && !st.IsDir():
			sum.Problems = append(sum.Problems, fmt.Sprintf("%s already exists and is not a folder", d))
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			sum.Problems = append(sum.Problems, fmt.Sprintf("can't create %s: %v", d, cleanErr(err)))
		}
	}
	sum.Needed = total - sum.PartialBytes - sum.ExistingSize
	if free, err := freeSpace(r.root); err == nil {
		sum.FreeSpace = free
		if sum.Needed > free {
			sum.Problems = append(sum.Problems, fmt.Sprintf("not enough free space: need %s, have %s", FormatBytes(sum.Needed), FormatBytes(free)))
		}
	}
	return local, sum
}

// cleanErr strips the path from file system errors (we print our own).
func cleanErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func (r *receiver) hashLocalPrefix(name string, n int64) (hash.Hash, error) {
	f, err := r.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, f, n); err != nil {
		return nil, err
	}
	return h, nil
}

// partName returns the name of the partial file for p, in the same folder.
func partName(p string) string {
	dir, base := path.Split(p)
	if len(base)+len(PartSuffix) > MaxNameLen {
		sum := sha256.Sum256([]byte(base))
		cut := MaxNameLen - len(PartSuffix) - 17
		for cut > 0 && !isRuneStart(base[cut]) {
			cut--
		}
		base = fmt.Sprintf("%s-%x", base[:cut], sum[:8])
	}
	return dir + base + PartSuffix
}

func isRuneStart(b byte) bool { return b&0xc0 != 0x80 }

func (r *receiver) receiveFile(f File, off int64, h hash.Hash, p *Progress) (err error) {
	part := partName(f.Path)
	if dir := path.Dir(f.Path); dir != "." {
		if err := r.root.MkdirAll(dir, 0o777); err != nil {
			return fail("the receiver could not create a folder", fmt.Errorf("creating %s: %w", dir, cleanErr(err)))
		}
	}

	var out *os.File
	if off > 0 {
		out, err = r.root.OpenFile(part, os.O_WRONLY, 0)
		if err == nil {
			// The partial must still hold at least what was verified;
			// Truncate would otherwise pad it with zeros.
			var st fs.FileInfo
			if st, err = out.Stat(); err == nil && (!st.Mode().IsRegular() || st.Size() < off) {
				err = fmt.Errorf("%s changed while receiving; run toss again", part)
			}
			if err == nil {
				if err = out.Truncate(off); err == nil {
					_, err = out.Seek(off, io.SeekStart)
				}
			}
			if err != nil {
				out.Close()
			}
		}
	} else {
		h = sha256.New()
		if rerr := r.root.Remove(part); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = rerr
		} else {
			perm := os.FileMode(0o666)
			if f.Exec {
				perm = 0o777
			}
			out, err = r.root.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		}
	}
	if err != nil {
		return fail("the receiver could not write a file", fmt.Errorf("writing %s: %w", f.Path, cleanErr(err)))
	}
	// Close on every path; on success the close error matters.
	closed := false
	defer func() {
		if !closed {
			out.Close()
		}
	}()

	// Hashing and writing to disk run in their own goroutines, in
	// parallel with receiving the next chunks (see pipeline.go).
	if r.pool == nil {
		r.pool = newChunkPool(maxData)
	}
	toHash := make(chan *chunk, pipelineDepth)
	toWrite := make(chan *chunk, pipelineDepth)
	hashDone := make(chan struct{})
	writeErr := make(chan error, 1)
	var failed atomic.Bool
	go func() {
		for c := range toHash {
			h.Write(c.data[:c.n])
			c.release()
		}
		close(hashDone)
	}()
	go func() {
		var werr error
		for c := range toWrite {
			if werr == nil {
				if _, err := out.Write(c.data[:c.n]); err != nil {
					werr = err
					failed.Store(true)
				}
			}
			c.release()
		}
		writeErr <- werr
	}()
	stopped := false
	stopPipeline := func() error {
		if stopped {
			return nil
		}
		stopped = true
		close(toHash)
		close(toWrite)
		<-hashDone
		return <-writeErr
	}
	defer stopPipeline() // before out is closed

	for remaining := f.Size - off; remaining > 0 && !failed.Load(); {
		typ, data, err := r.fr.next()
		if err != nil {
			return err
		}
		if typ != frameData {
			return protoErr("got frame type %d in the middle of %s", typ, f.Path)
		}
		if int64(len(data)) > remaining {
			return protoErr("more data than announced for %s", f.Path)
		}
		c := <-r.pool
		c.n = copy(c.data, data)
		c.refs.Store(2)
		toHash <- c
		toWrite <- c
		remaining -= int64(len(data))
		p.Done += int64(len(data))
		if r.opts.Progress != nil {
			r.opts.Progress(*p)
		}
	}
	if err := stopPipeline(); err != nil {
		return fail("the receiver could not write a file (disk full?)", fmt.Errorf("writing %s: %w", f.Path, cleanErr(err)))
	}
	want, err := r.fr.expect(frameFileEnd, nil)
	if err != nil {
		return err
	}
	if len(want) != sha256.Size || !bytes.Equal(h.Sum(nil), want) {
		out.Close()
		closed = true
		r.root.Remove(part)
		return fail("checksum mismatch", fmt.Errorf("%s arrived corrupted (checksum mismatch); it was discarded, try again", f.Path))
	}
	closed = true
	if err := out.Close(); err != nil {
		return fail("the receiver could not write a file", fmt.Errorf("writing %s: %w", f.Path, cleanErr(err)))
	}
	return r.finish(f, part)
}

// finish sets metadata on a verified partial file and moves it into place.
func (r *receiver) finish(f File, part string) error {
	if runtime.GOOS != "windows" {
		if st, err := r.root.Lstat(part); err == nil {
			perm := st.Mode().Perm()
			if f.Exec {
				perm |= (perm & 0o444) >> 2
			} else {
				perm &^= 0o111
			}
			if perm != st.Mode().Perm() {
				r.root.Chmod(part, perm)
			}
		}
	}
	if f.MTime != 0 {
		r.root.Chtimes(part, time.Time{}, time.Unix(0, f.MTime))
	}
	if !r.opts.Overwrite {
		if _, err := r.root.Lstat(f.Path); err == nil {
			return fail("a file appeared on the receiver while receiving",
				fmt.Errorf("%s appeared while it was being received; the received copy is kept as %s", f.Path, part))
		}
	}
	if err := r.root.Rename(part, f.Path); err != nil {
		return fail("the receiver could not write a file", fmt.Errorf("moving %s into place: %w", f.Path, cleanErr(err)))
	}
	return nil
}

// FormatBytes formats n as a human-readable size, e.g. "1.5 GB".
func FormatBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

// TopLevel groups an offer by first path element for display: each entry
// is a top-level name with its file count and size.
type TopLevel struct {
	Name  string
	IsDir bool
	// Hidden is true for names starting with a dot, which file managers
	// and ls don't show.
	Hidden bool
	Files  int
	Size   int64
}

// Summarize returns the top-level entries of an offer in order.
func Summarize(o *Offer) []TopLevel {
	var out []TopLevel
	idx := map[string]int{}
	add := func(name string, isDir bool) int {
		if i, ok := idx[name]; ok {
			return i
		}
		idx[name] = len(out)
		out = append(out, TopLevel{Name: name, IsDir: isDir, Hidden: strings.HasPrefix(name, ".")})
		return len(out) - 1
	}
	for _, f := range o.Files {
		first, _, nested := strings.Cut(f.Path, "/")
		i := add(first, nested)
		out[i].Files++
		out[i].Size += f.Size
	}
	for _, d := range o.Dirs {
		first, _, _ := strings.Cut(d, "/")
		add(first, true)
	}
	return out
}
