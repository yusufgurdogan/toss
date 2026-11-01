//go:build !windows

package xfer

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSenderDoesNotBlockOnSwappedFIFO(t *testing.T) {
	srcDir, dst := t.TempDir(), t.TempDir()
	name := filepath.Join(srcDir, "f")
	writeFile(t, name, []byte("data"), 0o644)
	src := collect(t, name)
	os.Remove(name)
	if err := syscall.Mkfifo(name, 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan outcome, 1)
	go func() { done <- transfer(t, src, dst, SendOptions{}, ReceiveOptions{}) }()
	select {
	case o := <-done:
		var fc *fileChangedError
		if !errors.As(o.sendErr, &fc) {
			t.Fatalf("send error %v", o.sendErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sender blocked opening a FIFO")
	}
}
