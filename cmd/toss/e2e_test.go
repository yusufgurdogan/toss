package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These tests build the toss binary and run real senders and receivers on
// loopback. The receiver always uses the code@address form, so nothing is
// broadcast on the local network.

var tossBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "toss-e2e")
	if err != nil {
		panic(err)
	}
	tossBin = filepath.Join(dir, "toss")
	if runtime.GOOS == "windows" {
		tossBin += ".exe"
	}
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if out, err := exec.Command(goBin, "build", "-o", tossBin, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building toss: %v\n%s", err, out)
		os.Exit(1)
	}
	exit := m.Run()
	os.RemoveAll(dir)
	os.Exit(exit)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type proc struct {
	cmd *exec.Cmd
	out bytes.Buffer
}

func start(t *testing.T, stdin string, args ...string) *proc {
	t.Helper()
	p := &proc{cmd: exec.Command(tossBin, args...)}
	p.cmd.Stdin = strings.NewReader(stdin)
	p.cmd.Stdout = &p.out
	p.cmd.Stderr = &p.out
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.cmd.Process.Kill() })
	return p
}

// wait returns the exit code and output, failing the test after a timeout.
func (p *proc) wait(t *testing.T) (int, string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		p.cmd.Process.Kill()
		<-done
		t.Fatalf("toss %v timed out; output:\n%s", p.cmd.Args[1:], p.out.String())
	}
	return p.cmd.ProcessState.ExitCode(), p.out.String()
}

// pair runs a sender with the given arguments and a receiver for the same
// code, returning both exit codes and outputs.
func pair(t *testing.T, sendArgs []string, recvCode string, recvStdin string, recvArgs ...string) (sc int, sout string, rc int, rout string) {
	t.Helper()
	port := freePort(t)
	// --no-lan, --no-dht: tests must not join multicast groups on real
	// networks or talk to the real DHT. The receiver uses CODE@ADDRESS.
	s := start(t, "", append([]string{"send", "--no-lan", "--no-dht", "--port", fmt.Sprint(port)}, sendArgs...)...)
	time.Sleep(300 * time.Millisecond)
	r := start(t, recvStdin, append([]string{fmt.Sprintf("%s@127.0.0.1:%d", recvCode, port)}, recvArgs...)...)
	rc, rout = r.wait(t)
	sc, sout = s.wait(t)
	return
}

func randFile(t *testing.T, name string, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	rand.Read(b)
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return b
}

const testCode = "4321-acid-acorn-acre"

func TestTransfer(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	a := randFile(t, filepath.Join(src, "dir", "a.bin"), 3<<20)
	b := randFile(t, filepath.Join(src, "b.txt"), 10)
	sc, sout, rc, rout := pair(t, []string{"--code", testCode, filepath.Join(src, "dir"), filepath.Join(src, "b.txt")}, testCode, "", "--out", dst, "--yes")
	if sc != 0 || rc != 0 {
		t.Fatalf("exit codes %d/%d\nsender:\n%s\nreceiver:\n%s", sc, rc, sout, rout)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "dir", "a.bin")); !bytes.Equal(got, a) {
		t.Error("a.bin differs")
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "b.txt")); !bytes.Equal(got, b) {
		t.Error("b.txt differs")
	}
	for _, want := range []string{"toss " + testCode, "Sent 2 files"} {
		if !strings.Contains(sout, want) {
			t.Errorf("sender output lacks %q:\n%s", want, sout)
		}
	}
	for _, want := range []string{"The sender offers 2 files", "dir/", "Received 2 files"} {
		if !strings.Contains(rout, want) {
			t.Errorf("receiver output lacks %q:\n%s", want, rout)
		}
	}
}

func TestWrongCode(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	randFile(t, filepath.Join(src, "f"), 100)
	sc, sout, rc, rout := pair(t, []string{"--code", testCode, filepath.Join(src, "f")}, "4321-acid-acorn-acid", "", "--out", dst, "--yes")
	if sc == 0 || rc == 0 {
		t.Fatalf("exit codes %d/%d", sc, rc)
	}
	if !strings.Contains(sout, "wrong code") || !strings.Contains(rout, "Wrong code") {
		t.Errorf("sender:\n%s\nreceiver:\n%s", sout, rout)
	}
	if entries, _ := os.ReadDir(dst); len(entries) != 0 {
		t.Errorf("files written after a wrong code: %v", entries)
	}
}

func TestDeclineAtPrompt(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	randFile(t, filepath.Join(src, "f"), 100)
	sc, sout, rc, rout := pair(t, []string{"--code", testCode, filepath.Join(src, "f")}, testCode, "n\n", "--out", dst)
	if sc == 0 || rc == 0 {
		t.Fatalf("exit codes %d/%d", sc, rc)
	}
	if !strings.Contains(rout, "Receive? [y/N]") || !strings.Contains(rout, "Declined") || !strings.Contains(sout, "declined") {
		t.Errorf("sender:\n%s\nreceiver:\n%s", sout, rout)
	}
}

func TestResumeAndSkip(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	big := randFile(t, filepath.Join(src, "d", "big.bin"), 5<<20)
	small := randFile(t, filepath.Join(src, "d", "small.bin"), 1000)
	// As if a previous transfer was interrupted: small.bin done, big.bin
	// half there.
	os.MkdirAll(filepath.Join(dst, "d"), 0o755)
	os.WriteFile(filepath.Join(dst, "d", "small.bin"), small, 0o644)
	os.WriteFile(filepath.Join(dst, "d", "big.bin.toss-part"), big[:2<<20], 0o644)

	sc, sout, rc, rout := pair(t, []string{"--code", testCode, filepath.Join(src, "d")}, testCode, "", "--out", dst, "--yes")
	if sc != 0 || rc != 0 {
		t.Fatalf("exit codes %d/%d\nsender:\n%s\nreceiver:\n%s", sc, rc, sout, rout)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "d", "big.bin")); !bytes.Equal(got, big) {
		t.Error("big.bin differs")
	}
	if _, err := os.Stat(filepath.Join(dst, "d", "big.bin.toss-part")); err == nil {
		t.Error("partial file left behind")
	}
	for _, want := range []string{"Resuming 1 partly received file", "1 file(s) with the same name and size", "were already there"} {
		if !strings.Contains(rout, want) {
			t.Errorf("receiver output lacks %q:\n%s", want, rout)
		}
	}
}

func TestSensitiveFoldersNeedAReview(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	randFile(t, filepath.Join(src, "proj", ".git", "config"), 10)
	randFile(t, filepath.Join(src, "proj", "main.go"), 10)
	sc, sout, rc, rout := pair(t, []string{"--code", testCode, filepath.Join(src, "proj")}, testCode, "", "--out", dst, "--yes")
	if sc == 0 || rc == 0 {
		t.Fatalf("exit codes %d/%d", sc, rc)
	}
	for _, want := range []string{"proj/.git", "Not accepting this automatically"} {
		if !strings.Contains(rout, want) {
			t.Errorf("receiver output lacks %q:\n%s", want, rout)
		}
	}
	if !strings.Contains(sout, "declined") {
		t.Errorf("sender:\n%s", sout)
	}
	if entries, _ := os.ReadDir(dst); len(entries) != 0 {
		t.Errorf("wrote %v", entries)
	}
}

func TestConflict(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	randFile(t, filepath.Join(src, "f"), 100)
	os.WriteFile(filepath.Join(dst, "f"), []byte("mine"), 0o644)
	sc, sout, rc, rout := pair(t, []string{"--code", testCode, filepath.Join(src, "f")}, testCode, "", "--out", dst, "--yes")
	if sc == 0 || rc == 0 {
		t.Fatalf("exit codes %d/%d", sc, rc)
	}
	if !strings.Contains(rout, "f already exists") || !strings.Contains(rout, "--overwrite") || !strings.Contains(sout, "declined") {
		t.Errorf("sender:\n%s\nreceiver:\n%s", sout, rout)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "f")); string(got) != "mine" {
		t.Error("existing file was modified")
	}
}

func TestUsageErrors(t *testing.T) {
	for _, tt := range []struct {
		args []string
		exit int
		want string
	}{
		{[]string{"send"}, 2, "say what to send"},
		{[]string{"send", "--bogus", "x"}, 2, "flag provided but not defined"},
		{[]string{"send", "/definitely/not/here"}, 1, "no such file"},
		{[]string{"1234-acid-acorn"}, 1, "a code has"},
		{[]string{"1234-acid-acron-acre"}, 1, "not a code word"},
		{[]string{"a", "b"}, 2, "expected one code"},
		{[]string{"version"}, 0, "protocol 1"},
		{[]string{"help"}, 0, "Usage:"},
	} {
		exit, out := start(t, "", tt.args...).wait(t)
		if exit != tt.exit || !strings.Contains(out, tt.want) {
			t.Errorf("toss %v: exit %d, output:\n%s\nwant exit %d and %q", tt.args, exit, out, tt.exit, tt.want)
		}
	}
}

func TestParseArgs(t *testing.T) {
	for _, tt := range []struct {
		in   []string
		pos  string
		port int
	}{
		{[]string{"a", "--port", "5", "b"}, "a b", 5},
		{[]string{"--port=6", "a"}, "a", 6},
		{[]string{"a", "--", "--port", "b"}, "a --port b", 0},
		{[]string{"-port", "7", "--", "-x"}, "-x", 7},
	} {
		fs := newSendFlags()
		pos, err := parseArgs(fs.set, tt.in)
		if err != nil || strings.Join(pos, " ") != tt.pos || *fs.port != tt.port {
			t.Errorf("parseArgs(%q) = %q, port %d, %v", tt.in, pos, *fs.port, err)
		}
	}
}
