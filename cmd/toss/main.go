// Command toss sends files directly between two computers, end-to-end
// encrypted, with no servers in between.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/yusufgurdogan/toss/internal/code"
	"github.com/yusufgurdogan/toss/internal/connect"
	"github.com/yusufgurdogan/toss/internal/lan"
	"github.com/yusufgurdogan/toss/internal/secure"
	"github.com/yusufgurdogan/toss/internal/xfer"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = ""

// findTimeout is how long the receiver looks for the sender.
const findTimeout = 90 * time.Second

const usage = `toss sends files directly between two computers, end-to-end encrypted.
No servers, no relays: the data goes straight from one computer to the other.

Usage:
  toss send [options] FILE|FOLDER...   send files and print a code
  toss [receive] [options] [CODE]      receive files (asks for the code if not given)
  toss version                         print the version

Send options:
  --code CODE   use this code instead of a random one
  --port N      listen on TCP port N (default: 47924, or any free port if
                that's taken)
  --no-lan      don't answer local network searches; the code then includes
                this computer's address

Receive options:
  --out DIR     save into DIR (default: the current folder)
  --yes, -y     accept without asking
  --overwrite   replace existing files that are different

When receiving, the code can also come from the TOSS_CODE environment
variable or be typed at the prompt, which keeps it out of the process list on
shared computers.

Interrupted transfers resume: run the same send again and receive into the
same folder, and toss only transfers what is missing.

Codes look like 7392-river-moon-sun. A code works once: if someone tries a
wrong code, the sender stops and you need a new one.
`

var stderr io.Writer = os.Stderr

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// A second Ctrl-C kills the process immediately.
	context.AfterFunc(ctx, stop)
	err := run(ctx, os.Args[1:])
	stop()
	if err == nil {
		return
	}
	var ue *usageError
	switch {
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "toss: %v\nRun 'toss help' for usage.\n", ue.msg)
		os.Exit(2)
	case errors.Is(err, context.Canceled) || errors.Is(err, errSilent):
		os.Exit(1)
	default:
		fmt.Fprintf(stderr, "toss: %v\n", err)
		os.Exit(1)
	}
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usageErrorf(format string, args ...any) error {
	return &usageError{fmt.Sprintf(format, args...)}
}

// errSilent means the problem was already explained to the user.
var errSilent = errors.New("failed")

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return cmdReceive(ctx, nil)
	}
	switch args[0] {
	case "send", "s":
		return cmdSend(ctx, args[1:])
	case "receive", "recv", "r":
		return cmdReceive(ctx, args[1:])
	case "version", "--version", "-version", "-v":
		fmt.Printf("toss %s (protocol %d)\n", versionString(), secure.ProtocolVersion)
		return nil
	case "help", "--help", "-help", "-h":
		fmt.Print(usage)
		return nil
	}
	return cmdReceive(ctx, args)
}

func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// parseArgs parses flags anywhere among the arguments (toss send a.txt
// --port 9 works) and returns the positional arguments. "--" ends flags.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Print(usage)
				return nil, errSilent
			}
			return nil, usageErrorf("%v", err)
		}
		rest := fs.Args()
		// Parse stops at the first positional argument, or after "--".
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	return pos, nil
}

type sendFlags struct {
	set   *flag.FlagSet
	code  *string
	port  *int
	noLAN *bool
}

func newSendFlags() *sendFlags {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	return &sendFlags{
		set:   fs,
		code:  fs.String("code", "", ""),
		port:  fs.Int("port", 0, ""),
		noLAN: fs.Bool("no-lan", false, ""),
	}
}

func cmdSend(ctx context.Context, args []string) error {
	flags := newSendFlags()
	codeFlag, port := flags.code, flags.port
	paths, err := parseArgs(flags.set, args)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return usageErrorf("say what to send: toss send FILE|FOLDER...")
	}
	if *port < 0 || *port > 65535 {
		return usageErrorf("--port must be between 1 and 65535")
	}

	src, err := xfer.Collect(paths)
	if err != nil {
		return err
	}
	if n := len(src.Skipped); n > 0 {
		fmt.Fprintf(stderr, "Skipping %d symbolic link(s) or special file(s), which toss doesn't send:\n", n)
		for i, p := range src.Skipped {
			if i == 5 {
				fmt.Fprintf(stderr, "  ... and %d more\n", n-5)
				break
			}
			fmt.Fprintf(stderr, "  %s\n", p)
		}
	}

	var c code.Code
	if *codeFlag != "" {
		if c, err = code.Parse(*codeFlag); err != nil {
			return usageErrorf("--code: %v", err)
		}
		if c.Addr != "" {
			return usageErrorf("--code: leave out the @address part")
		}
		fmt.Fprintln(stderr, "Note: every send with the same chosen code gives an eavesdropper another guess,")
		fmt.Fprintln(stderr, "and other users of this computer can see it in the process list. A fresh random")
		fmt.Fprintln(stderr, "code (the default) is safer.")
	} else if c, err = code.Generate(); err != nil {
		return err
	}

	ln, err := listen(*port)
	if err != nil {
		return err
	}
	defer ln.Close()
	tcpPort := ln.Addr().(*net.TCPAddr).Port

	var responder *lan.Responder
	if !*flags.noLAN {
		responder, err = lan.Listen(c.MeetingID(), tcpPort, lan.ListenOptions{})
		if err != nil {
			fmt.Fprintf(stderr, "Note: can't answer local network searches (%v); the receiver needs the code@address form.\n", err)
		} else {
			defer responder.Close()
		}
	}
	srv, err := secure.NewServer(c.Password())
	if err != nil {
		return err
	}

	fmt.Fprintf(stderr, "Sending %s.\n\n", describe(len(src.Offer.Files), src.Total))
	// One code to read out. An address is only mentioned when it's
	// needed: as a hint when this computer is reachable from other
	// networks, or as part of the code with --no-lan.
	public, private := lan.Addrs()
	portStr := fmt.Sprint(tcpPort)
	if *flags.noLAN {
		addr := "ADDRESS"
		if a, ok := bestAddr(public, private); ok {
			addr = a.String()
		}
		fmt.Fprintf(stderr, "On the other computer, run:\n\n    toss %s\n\n", c.WithAddr(net.JoinHostPort(addr, portStr)))
		if addr == "ADDRESS" {
			fmt.Fprintln(stderr, "(ADDRESS is this computer's IP address.)")
			fmt.Fprintln(stderr)
		}
	} else {
		fmt.Fprintf(stderr, "On the other computer, run:\n\n    toss %s\n\n", c)
		if a, ok := bestAddr(public, nil); ok {
			fmt.Fprintf(stderr, "From another network, add this computer's address to the end of the code: @%s\n\n", net.JoinHostPort(a.String(), portStr))
		}
	}
	fmt.Fprintln(stderr, "Waiting for the receiver... (Ctrl-C to cancel)")

	warned := false
	tc, err := connect.Serve(ctx, ln, srv, func(err error) {
		var ve *secure.VersionError
		if errors.As(err, &ve) && !warned {
			warned = true
			fmt.Fprintf(stderr, "A receiver connected but can't be served: %v\n", err)
		}
	})
	if responder != nil {
		responder.Close()
	}
	if err != nil {
		if errors.Is(err, secure.ErrWrongCode) {
			fmt.Fprintln(stderr, "\nSomeone tried to receive with a wrong code. For safety this code no longer works.")
			fmt.Fprintln(stderr, "Run toss send again to get a new code.")
			return errSilent
		}
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "\nCancelled.")
			return errSilent
		}
		if errors.Is(err, secure.ErrLostAfterProof) {
			fmt.Fprintln(stderr, "\nThe receiver connected with the right code, but the connection broke.")
			fmt.Fprintln(stderr, "Codes work once: run toss send again to get a new code.")
			return errSilent
		}
		return err
	}
	fmt.Fprintf(stderr, "Connected to %s. Waiting for the receiver to accept...\n", tc.RemoteAddr())

	bar := newProgressBar(stderr)
	start := time.Now()
	res, err := xfer.Send(ctx, tc, src, xfer.SendOptions{
		Progress: bar.update,
		Accepted: func() { fmt.Fprintln(stderr, "Accepted.") },
	})
	bar.done()
	if err != nil {
		var de *xfer.DeclinedError
		switch {
		case errors.As(err, &de):
			return errors.New(de.Error())
		case errors.Is(err, context.Canceled):
			fmt.Fprintln(stderr, "\nCancelled.")
			return errSilent
		}
		return fmt.Errorf("transfer failed: %w", err)
	}
	fmt.Fprintf(stderr, "Sent %s%s.\n", describe(res.Files, res.Bytes+res.Resumed), resumeNote(res, time.Since(start)))
	return nil
}

// bestAddr picks the address most likely to work for a receiver: public
// before private, IPv4 (shorter, more widely routable) before IPv6.
func bestAddr(public, private []netip.Addr) (netip.Addr, bool) {
	for _, group := range [][]netip.Addr{public, private} {
		for _, want4 := range []bool{true, false} {
			for _, a := range group {
				if a.Is4() == want4 {
					return a, true
				}
			}
		}
	}
	return netip.Addr{}, false
}

// defaultTCPPort is where the sender listens unless it's taken (another
// toss is sending) or --port says otherwise. A fixed default lets people
// open it once in a firewall or forward it on a router.
const defaultTCPPort = 47924

func listen(port int) (net.Listener, error) {
	if port != 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return nil, fmt.Errorf("can't listen on port %d: %w", port, err)
		}
		return ln, nil
	}
	if ln, err := net.Listen("tcp", fmt.Sprintf(":%d", defaultTCPPort)); err == nil {
		return ln, nil
	}
	return net.Listen("tcp", ":0")
}

func cmdReceive(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("receive", flag.ContinueOnError)
	out := fs.String("out", ".", "")
	yes := fs.Bool("yes", false, "")
	fs.BoolVar(yes, "y", false, "")
	overwrite := fs.Bool("overwrite", false, "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usageErrorf("expected one code, got %d arguments (to send files, use toss send)", len(pos))
	}

	stdin := bufio.NewReader(os.Stdin)
	var codeStr string
	switch {
	case len(pos) == 1:
		codeStr = pos[0]
	case os.Getenv("TOSS_CODE") != "":
		codeStr = os.Getenv("TOSS_CODE")
	default:
		if len(args) == 0 {
			fmt.Fprintln(stderr, "Receiving. (To send files instead, run: toss send FILE|FOLDER...)")
		}
		fmt.Fprint(stderr, "Enter the code from the sender: ")
		line, err := stdin.ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(stderr)
			return usageErrorf("no code given")
		}
		codeStr = line
	}
	c, err := code.Parse(codeStr)
	if err != nil {
		if _, statErr := os.Stat(strings.TrimSpace(codeStr)); statErr == nil && len(pos) == 1 {
			return usageErrorf("%v\n(to send %s, run: toss send %s)", err, codeStr, codeStr)
		}
		return err
	}

	if err := os.MkdirAll(*out, 0o777); err != nil {
		return err
	}
	absOut, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(absOut)
	if err != nil {
		return err
	}
	defer root.Close()

	if c.Addr != "" {
		fmt.Fprintf(stderr, "Connecting to the sender at %s...\n", c.Addr)
	} else {
		fmt.Fprintln(stderr, "Looking for the sender on this network...")
	}
	dctx, cancel := context.WithTimeout(ctx, findTimeout)
	// With an address in the code, connect only there: no need to
	// announce the meeting ID on the local network.
	tc, err := connect.Dial(dctx, c, connect.DialOptions{NoLAN: c.Addr != ""})
	cancel()
	if err != nil {
		return explainDialError(err)
	}
	fmt.Fprintf(stderr, "Connected to %s.\n", tc.RemoteAddr())

	bar := newProgressBar(stderr)
	start := time.Now()
	res, err := xfer.Receive(ctx, tc, root, xfer.ReceiveOptions{
		Overwrite: *overwrite,
		Confirm: func(s *xfer.Summary) bool {
			showSummary(s, absOut, *overwrite)
			if *yes {
				if len(s.Sensitive) > 0 {
					fmt.Fprintln(stderr, "Not accepting this automatically because of the folders above.")
					fmt.Fprintln(stderr, "Run without --yes to review it.")
					return false
				}
				return true
			}
			return askYes(stdin, "Receive? [y/N] ")
		},
		Progress: bar.update,
		Status:   func(s string) { fmt.Fprintln(stderr, s) },
	})
	bar.done()
	if err != nil {
		return explainReceiveError(err)
	}
	fmt.Fprintf(stderr, "Received %s into %s%s.\n", describe(res.Files, res.Bytes+res.Resumed), absOut, resumeNote(res, time.Since(start)))
	return nil
}

func explainDialError(err error) error {
	var spe *secure.SentProofError
	var ve *secure.VersionError
	var nf *connect.NotFoundError
	switch {
	case errors.Is(err, secure.ErrWrongCode):
		fmt.Fprintln(stderr, "Wrong code. For safety the sender's code no longer works:")
		fmt.Fprintln(stderr, "ask them to run toss send again and give you the new code.")
		return errSilent
	case errors.Is(err, secure.ErrRefused):
		fmt.Fprintln(stderr, "The sender no longer accepts this code (it was used already, or someone")
		fmt.Fprintln(stderr, "tried a wrong one). Ask them to run toss send again for a new code.")
		return errSilent
	case errors.Is(err, secure.ErrConfirmLost):
		fmt.Fprintln(stderr, "The connection dropped while checking the code. Ask the sender for a new code.")
		return errSilent
	case errors.As(err, &spe):
		// Anything else after our proof of the code: the code may have
		// been used up, possibly by someone pretending to be the sender.
		fmt.Fprintf(stderr, "Checking the code failed (%v).\n", spe.Err)
		fmt.Fprintln(stderr, "Don't retry with this code: ask the sender to run toss send again for a new one.")
		return errSilent
	case errors.As(err, &ve):
		return err
	case errors.As(err, &nf):
		fmt.Fprintf(stderr, "%v.\n", nf)
		if nf.Addr == "" {
			fmt.Fprintln(stderr, "Check that toss send is running with this code and that both computers are on")
			fmt.Fprintln(stderr, "the same network. From another network, add the sender's address to the code:")
			fmt.Fprintln(stderr, "toss CODE@ADDRESS:PORT (toss send shows it when it has a public address).")
		} else {
			fmt.Fprintln(stderr, "Check that toss send is still running and that no firewall blocks the port.")
		}
		return errSilent
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(stderr, "\nCancelled.")
		return errSilent
	}
	return fmt.Errorf("couldn't connect: %w", err)
}

func explainReceiveError(err error) error {
	var ce *xfer.ConflictError
	var ue *xfer.UnsafeOfferError
	switch {
	case errors.Is(err, xfer.ErrDeclined):
		fmt.Fprintln(stderr, "Declined.")
		return errSilent
	case errors.As(err, &ce):
		fmt.Fprintln(stderr, "Can't receive here:")
		for i, p := range ce.Problems {
			if i == 10 {
				fmt.Fprintf(stderr, "  ... and %d more\n", len(ce.Problems)-10)
				break
			}
			fmt.Fprintf(stderr, "  %s\n", p)
		}
		fmt.Fprintln(stderr, "Use --out to receive into another folder, or --overwrite to replace different files.")
		return errSilent
	case errors.As(err, &ue):
		return err
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(stderr, "\nInterrupted. What arrived is kept: get a new code from the sender and")
		fmt.Fprintln(stderr, "receive into the same folder to resume.")
		return errSilent
	}
	fmt.Fprintf(stderr, "\nTransfer failed: %v\n", err)
	fmt.Fprintln(stderr, "What arrived is kept: get a new code from the sender and receive into the same folder to resume.")
	return errSilent
}

func showSummary(s *xfer.Summary, dir string, overwrite bool) {
	fmt.Fprintf(stderr, "The sender offers %s:\n", describe(len(s.Offer.Files), s.Total))
	// Everything that lands directly in the destination is listed, except
	// that a long run of ordinary files is shortened: folders and hidden
	// entries are always shown, since they can carry anything.
	const maxPlainFiles = 20
	plain, hiddenPlain := 0, 0
	for _, t := range xfer.Summarize(&s.Offer) {
		switch {
		case t.IsDir:
			fmt.Fprintf(stderr, "  %s/  (%s)\n", t.Name, describe(t.Files, t.Size))
		case t.Hidden || plain < maxPlainFiles:
			fmt.Fprintf(stderr, "  %s  (%s)\n", t.Name, xfer.FormatBytes(t.Size))
			if !t.Hidden {
				plain++
			}
		default:
			hiddenPlain++
		}
	}
	if hiddenPlain > 0 {
		fmt.Fprintf(stderr, "  ... and %d more file(s)\n", hiddenPlain)
	}
	fmt.Fprintf(stderr, "into %s\n", dir)
	if home, err := os.UserHomeDir(); err == nil && sameDir(home, dir) {
		fmt.Fprintln(stderr, "Note: that is your home folder, where some files and folders (shell profiles,")
		fmt.Fprintln(stderr, "autostart entries) run programs. Consider --out with a new folder.")
	}
	if n := len(s.Sensitive); n > 0 {
		fmt.Fprintln(stderr, "Careful: these folders can hold keys or run code when used:")
		list(s.Sensitive, 10)
	}
	if n := len(s.Executables); n > 0 {
		fmt.Fprintf(stderr, "Programs and scripts (%d):\n", n)
		list(s.Executables, 10)
	}
	if s.Partial > 0 {
		fmt.Fprintf(stderr, "Resuming %d partly received file(s) (%s already here).\n", s.Partial, xfer.FormatBytes(s.PartialBytes))
	}
	if s.Existing > 0 {
		if overwrite {
			fmt.Fprintf(stderr, "%d file(s) with the same name and size are already here; identical ones will be skipped, different ones replaced.\n", s.Existing)
		} else {
			fmt.Fprintf(stderr, "%d file(s) with the same name and size are already here; identical ones will be skipped.\n", s.Existing)
		}
	}
	if n := len(s.Replace); n > 0 {
		fmt.Fprintf(stderr, "These %d existing file(s) will be replaced (--overwrite):\n", n)
		list(s.Replace, 20)
	}
}

func list(items []string, max int) {
	for i, it := range items {
		if i == max {
			fmt.Fprintf(stderr, "    ... and %d more\n", len(items)-max)
			return
		}
		fmt.Fprintf(stderr, "    %s\n", it)
	}
}

func sameDir(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

// askYes asks a yes/no question that defaults to no. Anything typed before
// the question appeared (say, an extra Enter pasted with the code) is
// thrown away first, so it can't answer for the user.
func askYes(r *bufio.Reader, prompt string) bool {
	if isTerminal(os.Stdin) {
		r.Discard(r.Buffered())
	}
	fmt.Fprint(stderr, prompt)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(stderr, "\n(no answer; use --yes to accept without asking)")
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func describe(files int, bytes int64) string {
	noun := "files"
	if files == 1 {
		noun = "file"
	}
	return fmt.Sprintf("%d %s, %s", files, noun, xfer.FormatBytes(bytes))
}

func resumeNote(res *xfer.Result, elapsed time.Duration) string {
	var parts []string
	if res.Resumed > 0 {
		parts = append(parts, xfer.FormatBytes(res.Resumed)+" were already there")
	}
	if res.Bytes > 0 && elapsed > 0 {
		parts = append(parts, fmt.Sprintf("%s in %s, %s/s", xfer.FormatBytes(res.Bytes), roundDuration(elapsed), xfer.FormatBytes(int64(float64(res.Bytes)/elapsed.Seconds()))))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

func roundDuration(d time.Duration) time.Duration {
	if d < time.Second {
		return d.Round(time.Millisecond)
	}
	return d.Round(100 * time.Millisecond)
}
