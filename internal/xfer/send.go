package xfer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"
)

// Progress reports transfer progress. Done and Total count the bytes moved
// in this session; Resumed counts bytes the receiver already had.
type Progress struct {
	Done, Total int64
	Resumed     int64
	File        string // path of the file being transferred
}

// SendOptions configures Send.
type SendOptions struct {
	// Progress, if set, is called from the sending goroutine as data is
	// sent. It must return quickly.
	Progress func(Progress)
	// Accepted, if set, is called once the receiver has accepted.
	Accepted func()
}

// Result describes a finished transfer.
type Result struct {
	Files     int   // files in the offer
	Bytes     int64 // bytes moved in this session
	Resumed   int64 // bytes the receiver already had (resumed or identical)
	Unchanged int   // files skipped because the receiver already had them
}

// DeclinedError means the receiver declined the offer.
type DeclinedError struct{ Reason string }

func (e *DeclinedError) Error() string {
	if e.Reason == "" {
		return "the receiver declined"
	}
	return "the receiver declined: " + e.Reason
}

// Send runs the sender side of the transfer protocol over conn, which must
// already be secured. conn is closed when Send returns.
func Send(ctx context.Context, conn io.ReadWriteCloser, src *Source, opts SendOptions) (*Result, error) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	res, err := send(conn, src, opts)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil && connLost(err) {
		return nil, ErrReceiverGone
	}
	return res, err
}

func send(conn io.ReadWriteCloser, src *Source, opts SendOptions) (*Result, error) {
	files := src.Offer.Files
	fr := newFrameReader(conn)

	if err := writeJSON(conn, frameOffer, &src.Offer); err != nil {
		return nil, err
	}
	var acc Accept
	if _, err := fr.expect(frameAccept, &acc); err != nil {
		return nil, err
	}
	if !acc.OK {
		return nil, &DeclinedError{Reason: sanitize(acc.Reason)}
	}
	if opts.Accepted != nil {
		opts.Accepted()
	}

	// Answer the receiver's resume checks with our own prefix hashes.
	if len(acc.Check) > len(files) {
		return nil, protoErr("too many checks")
	}
	checked := make(map[int]int64, len(acc.Check))
	for _, c := range acc.Check {
		if c.I < 0 || c.I >= len(files) || c.N <= 0 || c.N > files[c.I].Size {
			return nil, protoErr("bad check %+v", c)
		}
		if _, dup := checked[c.I]; dup {
			return nil, protoErr("duplicate check for file %d", c.I)
		}
		checked[c.I] = c.N
	}
	states := make([]hash.Hash, len(acc.Check))
	plan := Plan{Hashes: make([][]byte, len(acc.Check))}
	parallel(len(acc.Check), func(k int) {
		c := acc.Check[k]
		h, err := hashPrefix(src, c.I, c.N)
		if err != nil {
			return // our file is shorter or unreadable now: no match
		}
		states[k] = h
		plan.Hashes[k] = h.Sum(nil)
	})
	if err := writeJSON(conn, framePlan, &plan); err != nil {
		return nil, err
	}
	stateOf := make(map[int]hash.Hash, len(acc.Check))
	for k, c := range acc.Check {
		if states[k] != nil {
			stateOf[c.I] = states[k]
		}
	}

	var start Start
	if _, err := fr.expect(frameStart, &start); err != nil {
		return nil, err
	}
	from := make(map[int]int64, len(start.From))
	for _, c := range start.From {
		if n, ok := checked[c.I]; !ok || n != c.N || stateOf[c.I] == nil {
			return nil, protoErr("resume request %+v does not match a check", c)
		}
		if _, dup := from[c.I]; dup {
			return nil, protoErr("duplicate resume request for file %d", c.I)
		}
		from[c.I] = c.N
	}
	skip := make(map[int]bool, len(start.Skip))
	for _, i := range start.Skip {
		if i < 0 || i >= len(files) || skip[i] {
			return nil, protoErr("bad skip %d", i)
		}
		if _, resumed := from[i]; resumed {
			return nil, protoErr("file %d both skipped and resumed", i)
		}
		skip[i] = true
	}

	res := &Result{Files: len(files)}
	var total int64
	for i, f := range files {
		switch {
		case skip[i]:
			res.Unchanged++
			res.Resumed += f.Size
		default:
			res.Resumed += from[i]
			total += f.Size - from[i]
		}
	}

	// From now on the receiver only talks to say Done or report an error.
	peer := make(chan error, 1)
	go func() {
		typ, _, err := fr.next()
		if err == nil && typ != frameDone {
			err = protoErr("unexpected frame type %d during transfer", typ)
		}
		if err != nil {
			conn.Close() // unblock our writes
		}
		peer <- err
	}()

	p := Progress{Total: total, Resumed: res.Resumed}
	pool := newChunkPool(headerLen + dataChunk)
	for i, f := range files {
		if skip[i] {
			continue
		}
		p.File = f.Path
		h := stateOf[i]
		if from[i] == 0 {
			h = sha256.New()
		}
		if err := sendFile(conn, src, i, from[i], h, pool, &p, opts.Progress); err != nil {
			// If the receiver stopped us, its reason is more useful
			// than our write error. It arrives quickly or not at all.
			select {
			case perr := <-peer:
				var pe *PeerError
				if errors.As(perr, &pe) {
					return nil, perr
				}
			case <-time.After(2 * time.Second):
			}
			return nil, err
		}
	}
	if err := <-peer; err != nil {
		return nil, err
	}
	res.Bytes = p.Done
	return res, nil
}

// fileChangedError is reported to the receiver as well.
type fileChangedError struct{ path string }

func (e *fileChangedError) Error() string {
	return fmt.Sprintf("%s changed while it was being sent", e.path)
}

type sendItem struct {
	c   *chunk
	err error
}

// sendFile streams bytes [off, f.Size) of the local file as Data frames,
// followed by FileEnd with the SHA-256 of the whole file (h holds the
// state after the first off bytes). Reading, hashing and sending run in
// parallel (see pipeline.go).
func sendFile(conn io.Writer, src *Source, i int, off int64, h hash.Hash, pool chan *chunk, p *Progress, progress func(Progress)) error {
	f, local := src.Offer.Files[i], src.Local[i]
	fh, err := src.open(i)
	if err != nil {
		var fc *fileChangedError
		if errors.As(err, &fc) {
			writeError(conn, fc.Error())
			return err
		}
		writeError(conn, fmt.Sprintf("can't read %s", f.Path))
		return err
	}
	defer fh.Close()
	if _, err := fh.Seek(off, io.SeekStart); err != nil {
		return err
	}

	toSend := make(chan sendItem, pipelineDepth)
	toHash := make(chan *chunk, pipelineDepth)
	quit := make(chan struct{})
	hashDone := make(chan struct{})
	go func() {
		for c := range toHash {
			h.Write(c.data[headerLen : headerLen+c.n])
			c.release()
		}
		close(hashDone)
	}()
	go func() {
		defer close(toSend)
		defer close(toHash)
		for remaining := f.Size - off; remaining > 0; {
			var c *chunk
			select {
			case c = <-pool:
			case <-quit:
				return
			}
			c.n = int(min(remaining, dataChunk))
			if _, err := io.ReadFull(fh, c.data[headerLen:headerLen+c.n]); err != nil {
				pool <- c
				toSend <- sendItem{err: err}
				return
			}
			c.refs.Store(2)
			toHash <- c
			toSend <- sendItem{c: c}
			remaining -= int64(c.n)
		}
	}()
	stop := func() {
		close(quit)
		for it := range toSend { // let the reader finish
			if it.c != nil {
				it.c.release()
			}
		}
		<-hashDone
	}

	for it := range toSend {
		if it.err != nil {
			stop()
			if errors.Is(it.err, io.EOF) || errors.Is(it.err, io.ErrUnexpectedEOF) {
				e := &fileChangedError{f.Path}
				writeError(conn, e.Error())
				return e
			}
			writeError(conn, fmt.Sprintf("can't read %s", f.Path))
			return fmt.Errorf("reading %s: %w", local, it.err)
		}
		c := it.c
		c.data[0] = frameData
		binary.BigEndian.PutUint32(c.data[1:headerLen], uint32(c.n))
		_, err := conn.Write(c.data[:headerLen+c.n])
		n := c.n
		c.release()
		if err != nil {
			stop()
			return err
		}
		p.Done += int64(n)
		if progress != nil {
			progress(*p)
		}
	}
	<-hashDone // the hasher is done with h
	return writeFrame(conn, frameFileEnd, h.Sum(nil))
}

// hashPrefix returns a SHA-256 state that has absorbed the first n bytes of
// the file, or an error if the file is shorter.
func hashPrefix(src *Source, i int, n int64) (hash.Hash, error) {
	f, err := src.open(i)
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

// parallel runs fn(0..n-1) on a few goroutines.
func parallel(n int, fn func(int)) {
	const workers = 4
	var wg sync.WaitGroup
	next := make(chan int)
	for range min(n, workers) {
		wg.Go(func() {
			for k := range next {
				fn(k)
			}
		})
	}
	for k := range n {
		next <- k
	}
	close(next)
	wg.Wait()
}
