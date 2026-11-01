package xfer

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Regression tests for the findings of the first security review.

func TestSenderRefusesSwappedSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	srcDir, dst := t.TempDir(), t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	writeFile(t, secret, []byte("TOP SECRET"), 0o600)
	name := filepath.Join(srcDir, "share", "f")
	writeFile(t, name, []byte("harmless!!"), 0o644)
	src := collect(t, filepath.Join(srcDir, "share"))

	// After listing, someone swaps the file for a symlink to a secret.
	os.Remove(name)
	if err := os.Symlink(secret, name); err != nil {
		t.Fatal(err)
	}
	o := transfer(t, src, dst, SendOptions{}, ReceiveOptions{})
	var fc *fileChangedError
	if !errors.As(o.sendErr, &fc) {
		t.Fatalf("send error %v, want fileChangedError", o.sendErr)
	}
	filepath.WalkDir(dst, func(p string, d os.DirEntry, err error) error {
		if d != nil && d.Type().IsRegular() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("SECRET")) {
				t.Errorf("secret leaked into %s", p)
			}
		}
		return nil
	})
}

func TestPartSuffixAnyCase(t *testing.T) {
	for _, p := range []string{"x.TOSS-PART", "x.Toss-Part", "x.toſſ-part"} {
		if _, err := validateOffer(&Offer{Files: []File{{Path: p, Size: 1}}}); err == nil {
			t.Errorf("offer of %q accepted", p)
		}
	}
}

func TestInvisibleCharactersRejected(t *testing.T) {
	for _, p := range []string{
		"invoice\u200b.pdf", // zero width space
		"a\u2028b",          // line separator
		"soft\u00adhyphen",  // soft hyphen
		"a\u3164b",          // Hangul filler
		"a\ue000b",          // private use
		"a\u2060b",          // word joiner
		"a\U000e0041b",      // tag character
	} {
		if ValidatePath(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
	for _, p := range []string{"日本語 ファイル.txt", "café.txt", "a\u3000b", "Ünïcødé/ok"} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
	if got := sanitize(strings.Repeat("x", 5000)); len(got) > maxMessage+10 {
		t.Errorf("peer message not shortened: %d bytes", len(got))
	}
}

func TestAutomaticDeclineLooksLikeManualDecline(t *testing.T) {
	data := []byte("12345")
	reason := func(problem bool) string {
		srcDir, dst := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(srcDir, "f"), data, 0o644)
		opts := ReceiveOptions{Confirm: func(*Summary) bool { return false }}
		if problem {
			writeFile(t, filepath.Join(dst, "f"), []byte("other size"), 0o644)
			opts = ReceiveOptions{}
		}
		o := transfer(t, collect(t, filepath.Join(srcDir, "f")), dst, SendOptions{}, opts)
		var de *DeclinedError
		if !errors.As(o.sendErr, &de) {
			t.Fatalf("send error %v", o.sendErr)
		}
		return de.Reason
	}
	if a, b := reason(true), reason(false); a != b {
		t.Fatalf("sender can tell an automatic decline (%q) from a manual one (%q)", a, b)
	}
}

func TestResumeRefusesShrunkPartial(t *testing.T) {
	dst := t.TempDir()
	data := randBytes(3000)
	writeFile(t, filepath.Join(dst, "f"+PartSuffix), data[:2000], 0o644)
	fs, errc := startFake(t, dst, ReceiveOptions{})
	if err := writeJSON(fs.c, frameOffer, &Offer{Files: []File{{Path: "f", Size: 3000}}}); err != nil {
		t.Fatal(err)
	}
	var acc Accept
	if _, err := fs.fr.expect(frameAccept, &acc); err != nil || len(acc.Check) != 1 || acc.Check[0].N != 2000 {
		t.Fatalf("accept %+v, %v", acc, err)
	}
	time.Sleep(200 * time.Millisecond) // the receiver hashes its 2000 bytes
	// Someone shrinks the partial before the data arrives.
	os.Truncate(filepath.Join(dst, "f"+PartSuffix), 500)
	sum := sha256.Sum256(data[:2000])
	writeJSON(fs.c, framePlan, &Plan{Hashes: [][]byte{sum[:]}})
	var start Start
	if _, err := fs.fr.expect(frameStart, &start); err != nil || len(start.From) != 1 {
		t.Fatalf("start %+v, %v", start, err)
	}
	writeFrame(fs.c, frameData, data[2000:])
	full := sha256.Sum256(data)
	writeFrame(fs.c, frameFileEnd, full[:])
	if err := <-errc; err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("receive error %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "f")); err == nil {
		t.Fatal("a zero-padded file was accepted as verified")
	}
}

func TestNotable(t *testing.T) {
	o := &Offer{
		Files: []File{
			{Path: "proj/.git/config"}, {Path: "proj/.git/hooks/pre-commit", Exec: true},
			{Path: "proj/main.go"}, {Path: ".SSH/authorized_keys"}, {Path: "setup.EXE"},
			{Path: "a/b/run.sh"}, {Path: "notes.txt"},
		},
		Dirs: []string{"keys/.gnupg"},
	}
	if got := strings.Join(Sensitive(o), ","); got != "proj/.git,.SSH,keys/.gnupg" {
		t.Errorf("Sensitive = %s", got)
	}
	if got := strings.Join(Executables(o), ","); got != "proj/.git/hooks/pre-commit,setup.EXE,a/b/run.sh" {
		t.Errorf("Executables = %s", got)
	}
	top := Summarize(o)
	if !top[1].Hidden || top[1].Name != ".SSH" || top[0].Hidden {
		t.Errorf("Summarize = %+v", top)
	}
}

func TestWindowsDeviceNames(t *testing.T) {
	// Checked on every OS so the rule is tested even without Windows CI.
	for _, n := range []string{"NUL", "nul", "NUL.txt", "nul.tar.gz", "NUL .txt", "CON", "aux.log",
		"COM1", "com9.txt", "LPT3", "COM¹", "LPT².dat", "CONIN$", "conout$.x", "CLOCK$", "COM0"} {
		if !windowsDeviceName(n) {
			t.Errorf("%q not recognized as a Windows device name", n)
		}
	}
	for _, n := range []string{"NULL", "nul_", "CONSOLE.txt", "COM10", "COM", "LPT", "a.NUL", "AUXI", "photo.jpg", "COMA"} {
		if windowsDeviceName(n) {
			t.Errorf("%q wrongly treated as a Windows device name", n)
		}
	}
	if runtime.GOOS == "windows" {
		for _, p := range []string{"a/NUL.txt", "CON", "x/com1.log"} {
			if ValidatePath(p) == nil {
				t.Errorf("%q accepted on Windows", p)
			}
		}
	}
}
