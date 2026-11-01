package xfer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkTransfer measures one 256 MB file over loopback TCP (no TLS).
func BenchmarkTransfer(b *testing.B) {
	srcDir := b.TempDir()
	name := filepath.Join(srcDir, "f")
	f, _ := os.Create(name)
	chunk := randBytes(1 << 20)
	for range 256 {
		f.Write(chunk)
	}
	f.Close()
	src, err := Collect([]string{name})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(src.Total)
	for b.Loop() {
		dst := b.TempDir()
		a, c := benchPair(b)
		done := make(chan error)
		go func() {
			_, err := Send(context.Background(), a, src, SendOptions{})
			done <- err
		}()
		root, _ := os.OpenRoot(dst)
		if _, err := Receive(context.Background(), c, root, ReceiveOptions{}); err != nil {
			b.Fatal(err)
		}
		root.Close()
		if err := <-done; err != nil {
			b.Fatal(err)
		}
	}
}
