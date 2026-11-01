package xfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	return benchPair(t)
}

func benchPair(t testing.TB) (a, b net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	a, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b = <-ch
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func writeFile(t *testing.T, name string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, perm); err != nil {
		t.Fatal(err)
	}
}

func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

type outcome struct {
	sendRes, recvRes *Result
	sendErr, recvErr error
}

func transfer(t *testing.T, src *Source, dst string, sopts SendOptions, ropts ReceiveOptions) outcome {
	t.Helper()
	a, b := tcpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var o outcome
	done := make(chan struct{})
	go func() {
		o.sendRes, o.sendErr = Send(ctx, a, src, sopts)
		close(done)
	}()
	o.recvRes, o.recvErr = Receive(ctx, b, openRoot(t, dst), ropts)
	<-done
	return o
}

func collect(t *testing.T, paths ...string) *Source {
	t.Helper()
	src, err := Collect(paths)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// sameTree checks that every regular file under a exists under b with the
// same contents.
func sameTree(t *testing.T, a, b string) {
	t.Helper()
	filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(a, p)
		other := filepath.Join(b, rel)
		switch {
		case d.Type().IsRegular():
			x, _ := os.ReadFile(p)
			y, err := os.ReadFile(other)
			if err != nil || !bytes.Equal(x, y) {
				t.Errorf("%s differs: %v", rel, err)
			}
		case d.IsDir():
			if st, err := os.Stat(other); err != nil || !st.IsDir() {
				t.Errorf("folder %s missing: %v", rel, err)
			}
		}
		return nil
	})
}

func noPartials(t *testing.T, dir string) {
	t.Helper()
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if strings.HasSuffix(p, PartSuffix) {
			t.Errorf("leftover partial file %s", p)
		}
		return nil
	})
}

func TestSendReceiveTree(t *testing.T) {
	srcDir, dst := t.TempDir(), t.TempDir()
	tree := filepath.Join(srcDir, "tree")
	writeFile(t, filepath.Join(tree, "empty.txt"), nil, 0o644)
	writeFile(t, filepath.Join(tree, "small.txt"), []byte("hello"), 0o644)
	writeFile(t, filepath.Join(tree, "sub", "big.bin"), randBytes(3*dataChunk+17), 0o644)
	writeFile(t, filepath.Join(tree, "sub", "deeper", "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755)
	writeFile(t, filepath.Join(tree, "unicode – ünï.txt"), []byte("ü"), 0o644)
	if err := os.MkdirAll(filepath.Join(tree, "emptydir", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	os.Chtimes(filepath.Join(tree, "small.txt"), old, old)
	single := filepath.Join(srcDir, "single.dat")
	writeFile(t, single, randBytes(1000), 0o600)
	symlinkOK := os.Symlink("/etc/passwd", filepath.Join(tree, "link")) == nil

	src := collect(t, tree, single)
	if symlinkOK && len(src.Skipped) != 1 {
		t.Errorf("skipped = %v, want the symlink", src.Skipped)
	}
	var lastP Progress
	var confirmed *Summary
	o := transfer(t, src, dst, SendOptions{}, ReceiveOptions{
		Confirm:  func(s *Summary) bool { confirmed = s; return true },
		Progress: func(p Progress) { lastP = p },
	})
	if o.sendErr != nil || o.recvErr != nil {
		t.Fatalf("send %v, receive %v", o.sendErr, o.recvErr)
	}
	sameTree(t, tree, filepath.Join(dst, "tree"))
	sameTree(t, single, filepath.Join(dst, "single.dat"))
	noPartials(t, dst)
	if confirmed == nil || confirmed.Total != src.Total || len(confirmed.Problems) != 0 {
		t.Errorf("summary %+v", confirmed)
	}
	if o.sendRes.Bytes != src.Total || o.recvRes.Bytes != src.Total || lastP.Done != src.Total {
		t.Errorf("bytes: sent %d received %d progress %d, want %d", o.sendRes.Bytes, o.recvRes.Bytes, lastP.Done, src.Total)
	}
	if _, err := os.Lstat(filepath.Join(dst, "tree", "link")); err == nil {
		t.Error("symlink was transferred")
	}
	if st, err := os.Stat(filepath.Join(dst, "tree", "emptydir", "nested")); err != nil || !st.IsDir() {
		t.Error("empty folder missing")
	}
	if st, _ := os.Stat(filepath.Join(dst, "tree", "small.txt")); !st.ModTime().Equal(old) {
		t.Errorf("mtime %v, want %v", st.ModTime(), old)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(dst, "tree", "sub", "deeper", "run.sh")); st.Mode().Perm()&0o100 == 0 {
			t.Errorf("exec bit lost: %v", st.Mode())
		}
		if st, _ := os.Stat(filepath.Join(dst, "tree", "small.txt")); st.Mode().Perm()&0o111 != 0 {
			t.Errorf("exec bit added: %v", st.Mode())
		}
	}
}

func TestResumePartial(t *testing.T) {
	srcDir, dst := t.TempDir(), t.TempDir()
	data := randBytes(3*dataChunk + 5)
	writeFile(t, filepath.Join(srcDir, "f.bin"), data, 0o644)
	have := int64(dataChunk + dataChunk/2)
	writeFile(t, filepath.Join(dst, "f.bin"+PartSuffix), data[:have], 0o644)

	var sum *Summary
	o := transfer(t, collect(t, filepath.Join(srcDir, "f.bin")), dst, SendOptions{},
		ReceiveOptions{Confirm: func(s *Summary) bool { sum = s; return true }})
	if o.sendErr != nil || o.recvErr != nil {
		t.Fatalf("send %v, receive %v", o.sendErr, o.recvErr)
	}
	if sum.Partial != 1 || sum.PartialBytes != have {
		t.Errorf("summary partial %d/%d", sum.Partial, sum.PartialBytes)
	}
	if o.recvRes.Resumed != have || o.recvRes.Bytes != int64(len(data))-have || o.sendRes.Bytes != o.recvRes.Bytes {
		t.Errorf("resumed %d, moved %d/%d", o.recvRes.Resumed, o.sendRes.Bytes, o.recvRes.Bytes)
	}
	got, _ := os.ReadFile(filepath.Join(dst, "f.bin"))
	if !bytes.Equal(got, data) {
		t.Error("resumed file differs")
	}
	noPartials(t, dst)
}

func TestResumeMismatchStartsOver(t *testing.T) {
	srcDir, dst := t.TempDir(), t.TempDir()
	data := randBytes(2*dataChunk + 5)
	writeFile(t, filepath.Join(srcDir, "f.bin"), data, 0o644)
	writeFile(t, filepath.Join(dst, "f.bin"+PartSuffix), randBytes(dataChunk), 0o644)

	o := transfer(t, collect(t, filepath.Join(srcDir, "f.bin")), dst, SendOptions{}, ReceiveOptions{})
	if o.sendErr != nil || o.recvErr != nil {
		t.Fatalf("send %v, receive %v", o.sendErr, o.recvErr)
	}
	if o.recvRes.Resumed != 0 || o.recvRes.Bytes != int64(len(data)) {
		t.Errorf("resumed %d, moved %d", o.recvRes.Resumed, o.recvRes.Bytes)
	}
	got, _ := os.ReadFile(filepath.Join(dst, "f.bin"))
	if !bytes.Equal(got, data) {
		t.Error("file differs")
	}
	noPartials(t, dst)
}

func TestInterruptedThenResumed(t *testing.T) {
	srcDir, dst := t.TempDir(), t.TempDir()
	tree := filepath.Join(srcDir, "d")
	first := randBytes(2 * dataChunk)
	second := randBytes(4 * dataChunk)
	writeFile(t, filepath.Join(tree, "1.bin"), first, 0o644)
	writeFile(t, filepath.Join(tree, "2.bin"), second, 0o644)
	src := collect(t, tree)

	// Interrupt the receiver (like Ctrl-C) in the middle of the second file.
	a, b := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sendDone := make(chan error, 1)
	go func() {
		_, err := Send(context.Background(), a, src, SendOptions{})
		sendDone <- err
	}()
	_, err := Receive(ctx, b, openRoot(t, dst), ReceiveOptions{Progress: func(p Progress) {
		if p.Done >= int64(len(first))+2*dataChunk {
			cancel()
		}
	}})
	if err == nil {
		t.Fatal("interrupted receive succeeded")
	}
	<-sendDone
	if got, _ := os.ReadFile(filepath.Join(dst, "d", "1.bin")); !bytes.Equal(got, first) {
		t.Fatal("first file not completed before the cut")
	}
	st, err := os.Stat(filepath.Join(dst, "d", "2.bin"+PartSuffix))
	if err != nil || st.Size() == 0 {
		t.Fatalf("partial file missing after interruption: %v", err)
	}

	// Run again: 1.bin is identical and skipped, 2.bin resumes.
	o := transfer(t, collect(t, tree), dst, SendOptions{}, ReceiveOptions{})
	if o.sendErr != nil || o.recvErr != nil {
		t.Fatalf("send %v, receive %v", o.sendErr, o.recvErr)
	}
	if o.recvRes.Unchanged != 1 || o.recvRes.Resumed != int64(len(first))+st.Size() {
		t.Errorf("unchanged %d resumed %d", o.recvRes.Unchanged, o.recvRes.Resumed)
	}
	sameTree(t, tree, filepath.Join(dst, "d"))
	noPartials(t, dst)
}

func TestExistingFiles(t *testing.T) {
	data := randBytes(5000)
	setup := func(t *testing.T, existing []byte) (src *Source, dst string) {
		srcDir, dst := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(srcDir, "f"), data, 0o644)
		writeFile(t, filepath.Join(dst, "f"), existing, 0o644)
		return collect(t, filepath.Join(srcDir, "f")), dst
	}

	t.Run("identical is skipped", func(t *testing.T) {
		src, dst := setup(t, data)
		old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		os.Chtimes(filepath.Join(dst, "f"), old, old)
		o := transfer(t, src, dst, SendOptions{}, ReceiveOptions{})
		if o.sendErr != nil || o.recvErr != nil {
			t.Fatalf("send %v, receive %v", o.sendErr, o.recvErr)
		}
		if o.recvRes.Unchanged != 1 || o.recvRes.Bytes != 0 {
			t.Errorf("result %+v", o.recvRes)
		}
		if st, _ := os.Stat(filepath.Join(dst, "f")); !st.ModTime().Equal(old) {
			t.Error("identical file was touched")
		}
	})

	t.Run("same size different content conflicts", func(t *testing.T) {
		other := randBytes(len(data))
		src, dst := setup(t, other)
		o := transfer(t, src, dst, SendOptions{}, ReceiveOptions{})
		var ce *ConflictError
		var pe *PeerError
		if !errors.As(o.recvErr, &ce) || !errors.As(o.sendErr, &pe) {
			t.Fatalf("send %v, receive %v", o.sendErr, o.recvErr)
		}
		if got, _ := os.ReadFile(filepath.Join(dst, "f")); !bytes.Equal(got, other) {
			t.Error("existing file was modified")
		}
	})

	t.Run("different size conflicts before confirm", func(t *testing.T) {
		src, dst := setup(t, []byte("short"))
		asked := false
		o := transfer(t, src, dst, SendOptions{}, ReceiveOptions{Confirm: func(*Summary) bool { asked = true; return true }})
		var ce *ConflictError
		var de *DeclinedError
		if !errors.As(o.recvErr, &ce) || !errors.As(o.sendErr, &de) || asked {
			t.Fatalf("send %v, receive %v, asked %v", o.sendErr, o.recvErr, asked)
		}
	})

	t.Run("overwrite replaces", func(t *testing.T) {
		for _, existing := range [][]byte{[]byte("short"), randBytes(len(data))} {
			src, dst := setup(t, existing)
			o := transfer(t, src, dst, SendOptions{}, ReceiveOptions{Overwrite: true})
			if o.sendErr != nil || o.recvErr != nil {
				t.Fatalf("send %v, receive %v", o.sendErr, o.recvErr)
			}
			if got, _ := os.ReadFile(filepath.Join(dst, "f")); !bytes.Equal(got, data) {
				t.Error("file not replaced")
			}
		}
	})

	t.Run("folder in the way", func(t *testing.T) {
		srcDir, dst := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(srcDir, "f"), data, 0o644)
		os.MkdirAll(filepath.Join(dst, "f"), 0o755)
		o := transfer(t, collect(t, filepath.Join(srcDir, "f")), dst, SendOptions{}, ReceiveOptions{Overwrite: true})
		var ce *ConflictError
		if !errors.As(o.recvErr, &ce) {
			t.Fatalf("receive %v", o.recvErr)
		}
	})
}

func TestDecline(t *testing.T) {
	srcDir, dst := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(srcDir, "f"), []byte("x"), 0o644)
	o := transfer(t, collect(t, filepath.Join(srcDir, "f")), dst, SendOptions{},
		ReceiveOptions{Confirm: func(*Summary) bool { return false }})
	var de *DeclinedError
	if !errors.Is(o.recvErr, ErrDeclined) || !errors.As(o.sendErr, &de) {
		t.Fatalf("send %v, receive %v", o.sendErr, o.recvErr)
	}
	entries, _ := os.ReadDir(dst)
	if len(entries) != 0 {
		t.Errorf("declined transfer wrote %v", entries)
	}
}

func TestFileShrinksWhileSending(t *testing.T) {
	srcDir, dst := t.TempDir(), t.TempDir()
	name := filepath.Join(srcDir, "f")
	// Larger than the read-ahead of the sending pipeline.
	writeFile(t, name, randBytes(4*pipelineDepth*dataChunk), 0o644)
	src := collect(t, name)
	o := transfer(t, src, dst, SendOptions{Progress: func(p Progress) {
		if p.Done == dataChunk {
			os.Truncate(name, dataChunk+10)
		}
	}}, ReceiveOptions{})
	var fc *fileChangedError
	var pe *PeerError
	if !errors.As(o.sendErr, &fc) || !errors.As(o.recvErr, &pe) {
		t.Fatalf("send %v, receive %v", o.sendErr, o.recvErr)
	}
	if _, err := os.Stat(filepath.Join(dst, "f")); err == nil {
		t.Error("incomplete file was moved into place")
	}
}

func TestCollect(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a", "x"), []byte("1"), 0o644)
	writeFile(t, filepath.Join(dir, "b", "x"), []byte("2"), 0o644)
	if _, err := Collect([]string{filepath.Join(dir, "a", "x"), filepath.Join(dir, "b", "x")}); err == nil {
		t.Error("two arguments with the same name were accepted")
	}
	if _, err := Collect([]string{"/"}); err == nil {
		t.Error("root folder accepted")
	}
	if _, err := Collect(nil); err == nil {
		t.Error("empty argument list accepted")
	}
	writeFile(t, filepath.Join(dir, "c", "y"+PartSuffix), nil, 0o644)
	if _, err := Collect([]string{filepath.Join(dir, "c")}); err == nil {
		t.Error("partial file name accepted")
	}
	if runtime.GOOS != "windows" {
		writeFile(t, filepath.Join(dir, "d", "bad\x1bname"), nil, 0o644)
		if _, err := Collect([]string{filepath.Join(dir, "d")}); err == nil {
			t.Error("control character in name accepted")
		}
		// A symlink given directly is followed.
		os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "linked"))
		src, err := Collect([]string{filepath.Join(dir, "linked")})
		if err != nil || len(src.Offer.Files) != 1 || src.Offer.Files[0].Path != "linked/x" {
			t.Errorf("symlink argument: %v %+v", err, src)
		}
	}
}

// fakeSender speaks the protocol by hand so tests can misbehave.
type fakeSender struct {
	t  *testing.T
	c  net.Conn
	fr *frameReader
}

func startFake(t *testing.T, dst string, ropts ReceiveOptions) (*fakeSender, chan error) {
	a, b := tcpPair(t)
	errc := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := Receive(ctx, b, openRoot(t, dst), ropts)
		errc <- err
	}()
	return &fakeSender{t: t, c: a, fr: newFrameReader(a)}, errc
}

// offer sends o and, if the receiver accepts, runs Plan/Start with no
// resume. It returns whether the receiver accepted.
func (f *fakeSender) offer(o Offer) bool {
	if err := writeJSON(f.c, frameOffer, &o); err != nil {
		f.t.Fatal(err)
	}
	var acc Accept
	if _, err := f.fr.expect(frameAccept, &acc); err != nil || !acc.OK {
		return false
	}
	writeJSON(f.c, framePlan, &Plan{Hashes: make([][]byte, len(acc.Check))})
	var start Start
	if _, err := f.fr.expect(frameStart, &start); err != nil {
		f.t.Fatal(err)
	}
	return true
}

func TestMaliciousOffers(t *testing.T) {
	bad := []string{
		"", ".", "..", "../evil", "a/../../evil", "/etc/passwd", "a//b", "a/./b", "a/",
		`a\b`, `..\evil`, "a\x00b", "a\x1b[2Jb", "a\nb", "a\u202eb", "a\u2066b", "a\u0085b",
		"x" + PartSuffix, strings.Repeat("a", 256), strings.Repeat("a/", 200) + "a",
	}
	if runtime.GOOS == "windows" {
		bad = append(bad, "CON", "a/NUL.txt", "NUL .txt", "COM1.log", "C:/x", "a:b", "a.", "a ")
	}
	for _, p := range bad {
		dst := t.TempDir()
		fs, errc := startFake(t, dst, ReceiveOptions{})
		if fs.offer(Offer{Files: []File{{Path: p, Size: 1}}}) {
			t.Errorf("offer of %q was accepted", p)
		}
		var ue *UnsafeOfferError
		if err := <-errc; !errors.As(err, &ue) {
			t.Errorf("offer of %q: receive error %v", p, err)
		}
		if entries, _ := os.ReadDir(dst); len(entries) != 0 {
			t.Errorf("offer of %q created %v", p, entries)
		}
	}

	structural := []Offer{
		{Files: []File{{Path: "a", Size: 1}, {Path: "a", Size: 1}}},
		{Files: []File{{Path: "a", Size: 1}, {Path: "a/b", Size: 1}}},
		{Files: []File{{Path: "a", Size: 1}}, Dirs: []string{"a"}},
		{Files: []File{{Path: "a", Size: 1}}, Dirs: []string{"a/b"}},
		{Files: []File{{Path: "a", Size: -1}}},
		{Files: []File{{Path: "a", Size: 1 << 62}, {Path: "b", Size: 1 << 62}}},
		{Dirs: []string{"../up"}},
	}
	for _, o := range structural {
		dst := t.TempDir()
		fs, errc := startFake(t, dst, ReceiveOptions{})
		if fs.offer(o) {
			t.Errorf("offer %+v was accepted", o)
		}
		<-errc
	}
}

func TestSymlinkInDestinationCannotEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	outside, dst := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dst, "link")); err != nil {
		t.Fatal(err)
	}
	srcDir := t.TempDir()
	writeFile(t, filepath.Join(srcDir, "link", "pwned"), []byte("x"), 0o644)
	o := transfer(t, collect(t, filepath.Join(srcDir, "link")), dst, SendOptions{}, ReceiveOptions{Overwrite: true})
	if o.recvErr == nil {
		t.Error("receive through an escaping symlink succeeded")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote outside the destination: %v", entries)
	}
}

func TestBadData(t *testing.T) {
	offer := Offer{Files: []File{{Path: "f", Size: 10}}}

	t.Run("too much data", func(t *testing.T) {
		dst := t.TempDir()
		fs, errc := startFake(t, dst, ReceiveOptions{})
		if !fs.offer(offer) {
			t.Fatal("not accepted")
		}
		writeFrame(fs.c, frameData, make([]byte, 11))
		var pe *ProtocolError
		if err := <-errc; !errors.As(err, &pe) {
			t.Fatalf("receive error %v", err)
		}
		if _, err := os.Stat(filepath.Join(dst, "f")); err == nil {
			t.Error("file moved into place")
		}
	})

	t.Run("checksum mismatch", func(t *testing.T) {
		dst := t.TempDir()
		fs, errc := startFake(t, dst, ReceiveOptions{})
		if !fs.offer(offer) {
			t.Fatal("not accepted")
		}
		writeFrame(fs.c, frameData, make([]byte, 10))
		wrong := sha256.Sum256([]byte("something else"))
		writeFrame(fs.c, frameFileEnd, wrong[:])
		if err := <-errc; err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Fatalf("receive error %v", err)
		}
		entries, _ := os.ReadDir(dst)
		if len(entries) != 0 {
			t.Errorf("corrupt file kept: %v", entries)
		}
		// The sender is told why.
		if _, _, err := fs.fr.next(); err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Errorf("sender saw %v", err)
		}
	})

	t.Run("oversized frame", func(t *testing.T) {
		dst := t.TempDir()
		fs, errc := startFake(t, dst, ReceiveOptions{})
		if !fs.offer(offer) {
			t.Fatal("not accepted")
		}
		fs.c.Write([]byte{frameData, 0xff, 0xff, 0xff, 0xff})
		var pe *ProtocolError
		if err := <-errc; !errors.As(err, &pe) {
			t.Fatalf("receive error %v", err)
		}
	})

	t.Run("bad resume request", func(t *testing.T) {
		// A receiver asking to resume a file it never checked is refused.
		srcDir := t.TempDir()
		writeFile(t, filepath.Join(srcDir, "f"), randBytes(100), 0o644)
		a, b := tcpPair(t)
		errc := make(chan error, 1)
		go func() {
			_, err := Send(context.Background(), a, collect(t, filepath.Join(srcDir, "f")), SendOptions{})
			errc <- err
		}()
		fr := newFrameReader(b)
		fr.expect(frameOffer, nil)
		writeJSON(b, frameAccept, &Accept{OK: true})
		fr.expect(framePlan, nil)
		writeJSON(b, frameStart, &Start{From: []Check{{I: 0, N: 50}}})
		var pe *ProtocolError
		if err := <-errc; !errors.As(err, &pe) {
			t.Fatalf("send error %v", err)
		}
	})
}

func TestValidatePathInvalidUTF8(t *testing.T) {
	// JSON can't carry invalid UTF-8 (it becomes U+FFFD), but the
	// validator must reject it anyway.
	if ValidatePath("\xff\xfe") == nil {
		t.Error("invalid UTF-8 accepted")
	}
	if ValidatePath("ok/\ufffd.txt") != nil {
		t.Error("U+FFFD rejected")
	}
}

func TestPartName(t *testing.T) {
	if got := partName("a/b.txt"); got != "a/b.txt"+PartSuffix {
		t.Errorf("partName = %q", got)
	}
	long := strings.Repeat("é", 127) // 254 bytes
	got := partName("d/" + long)
	base := path.Base(got)
	if len(base) > MaxNameLen || !strings.HasSuffix(base, PartSuffix) || ValidatePath(got) != nil {
		t.Errorf("long partName %q (%d bytes)", base, len(base))
	}
	if partName("d/"+long) == partName("d/"+long[:252]+"ab") {
		t.Error("long partial names collide")
	}
}

func FuzzValidatePath(f *testing.F) {
	for _, s := range []string{"a", "a/b", "../x", "a/../b", "/x", "a\\b", "CON", "a\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if ValidatePath(p) != nil {
			return
		}
		if !filepath.IsLocal(filepath.FromSlash(p)) || path.Clean(p) != p || strings.HasPrefix(p, "/") {
			t.Fatalf("accepted unsafe path %q", p)
		}
		for _, part := range strings.Split(p, "/") {
			if part == ".." || part == "." || part == "" {
				t.Fatalf("accepted path %q with element %q", p, part)
			}
		}
		if strings.ContainsAny(p, "\x00\\\n\r\x1b") {
			t.Fatalf("accepted path %q with forbidden characters", p)
		}
	})
}

func FuzzFrames(f *testing.F) {
	f.Add([]byte{frameOffer, 0, 0, 0, 2, '{', '}'})
	f.Add([]byte{frameError, 0, 0, 0, 3, 'a', 0x1b, 'b'})
	f.Fuzz(func(t *testing.T, b []byte) {
		fr := newFrameReader(bytes.NewReader(b))
		for {
			_, _, err := fr.next()
			if err != nil {
				var pe *PeerError
				if errors.As(err, &pe) && strings.ContainsFunc(pe.Msg, unsafeRune) {
					t.Fatalf("unsanitized peer message %q", pe.Msg)
				}
				return
			}
		}
	})
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 999: "999 B", 1000: "1.0 kB", 1500000: "1.5 MB", 3e9: "3.0 GB"} {
		if got := FormatBytes(n); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
