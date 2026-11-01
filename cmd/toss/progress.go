package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yusufgurdogan/toss/internal/xfer"
)

// progressBar prints a single, regularly refreshed status line on a
// terminal, and nothing otherwise.
type progressBar struct {
	w     io.Writer
	tty   bool
	mu    sync.Mutex
	start time.Time
	last  time.Time
	width int
	p     xfer.Progress
	shown bool
}

func newProgressBar(w io.Writer) *progressBar {
	tty := false
	if f, ok := w.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			tty = true
		}
	}
	return &progressBar{w: w, tty: tty}
}

func (b *progressBar) update(p xfer.Progress) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.start.IsZero() {
		b.start = now
	}
	b.p = p
	if !b.tty || now.Sub(b.last) < 150*time.Millisecond && p.Done < p.Total {
		return
	}
	b.last = now
	b.draw(now)
}

func (b *progressBar) draw(now time.Time) {
	p := b.p
	pct := 100.0
	if p.Total > 0 {
		pct = float64(p.Done) * 100 / float64(p.Total)
	}
	line := fmt.Sprintf("  %3.0f%%  %s of %s", pct, xfer.FormatBytes(p.Done), xfer.FormatBytes(p.Total))
	if el := now.Sub(b.start).Seconds(); el > 0.5 && p.Done > 0 {
		rate := float64(p.Done) / el
		line += fmt.Sprintf("  %s/s", xfer.FormatBytes(int64(rate)))
		if p.Done < p.Total {
			line += "  " + formatETA(time.Duration(float64(p.Total-p.Done)/rate*float64(time.Second))) + " left"
		}
	}
	if pad := b.width - len(line); pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	b.width = len(line)
	fmt.Fprint(b.w, "\r"+line)
	b.shown = true
}

// done draws the final state and ends the line.
func (b *progressBar) done() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.tty || b.start.IsZero() {
		return
	}
	b.draw(time.Now())
	if b.shown {
		fmt.Fprintln(b.w)
	}
}

func formatETA(d time.Duration) string {
	d = d.Round(time.Second)
	h, m, s := int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}
