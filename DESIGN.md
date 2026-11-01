# toss — design notes

Peer-to-peer, end-to-end encrypted file transfer with **no relays and no servers
anyone has to run**, and as few dependencies as possible.

Status: milestone 1 (same network + direct address, with resume) implemented
and tested.

## Goals

- Data only ever flows directly between the two machines. No relay, ever.
- Encrypted and authenticated with a short human code (PAKE).
- Fast (direct path, pipelined I/O) and resumable.
- Tiny dependency surface: Go standard library + 2 crypto modules.
- When a direct connection is impossible (e.g. both sides behind carrier-grade
  NAT with no IPv6), fail clearly and explain why. No silent fallback.

## Layout

| Package           | Role                                                        |
|-------------------|-------------------------------------------------------------|
| `cmd/toss`        | CLI, prompts, progress bar, end-to-end tests                |
| `internal/code`   | code generation/parsing, EFF wordlist, typo suggestions     |
| `internal/cpace`  | CPace PAKE, vendored from filippo.io/cpace                  |
| `internal/secure` | preamble + TLS 1.3 + PAKE bound to exporter + confirmation  |
| `internal/lan`    | UDP discovery responder (sender) and search (receiver)      |
| `internal/connect`| sender accept loop / receiver dialing, one PAKE per attempt |
| `internal/xfer`   | transfer protocol, safe receive, resume, pipelines          |

## Code phrase

`7392-river-moon-sun`: 4 digits + 3 words from the EFF short wordlist #1
(1296 words, CC BY 3.0; "yo-yo" replaced by "yolk" because "-" separates
words). Custom codes (`--code`) must have the same shape, with 3–8 words.

- **Meeting ID** = `7392-river` (digits + first word, ~2^23.6). Used to find the
  peer (LAN discovery now, DHT later). Treated as public.
- **PAKE password** = the full code. An attacker who learns the meeting ID still
  needs the last two words (~2^20.7) and gets **one online guess**: the sender
  aborts after a failed handshake. Never derive anything published from the
  secret words (that would allow offline brute force).
- Optional direct address suffix: `7392-river-moon-sun@203.0.113.5:41234` or
  `...@[2001:db8::1]:41234`. The receiver then connects only there (no LAN
  broadcast).
- Parsing is lenient about case and separators, strict about words: unknown
  words are rejected locally with a "did you mean" suggestion, so typos don't
  burn codes.
- The code may also come from env `TOSS_CODE` or a prompt (keeps it out of `ps`).

## Finding each other (milestone 1)

1. **LAN discovery**, UDP port 47923 (IANA unassigned range 47810–47999).
   Receiver sends `toss1?` + lanID(16) + nonce(16) every second to
   239.255.116.115, 255.255.255.255, each interface's directed broadcast,
   `ff02::746f:7373%iface` and loopback. The sender listens with one
   `net.ListenMulticastUDP` socket per interface and family and replies by
   unicast: `toss1!` + lanID + nonce + TCP port. It answers each
   (nonce, source address) once. lanID = SHA-256("toss lan v1" || meetingID)[:16].
   The many targets are deliberate: multicast fails without a route,
   broadcast fails across some setups, IPv6 link-local usually just works.
2. **Direct address** from the code suffix. The sender shows one code; if it has
   a public address it adds a one-line hint to append `@address:port` for
   receivers on other networks (with `--no-lan` the address is part of the
   code). It listens on TCP 47924 by
   default (so a firewall rule or port forward can be set up once), falling
   back to a random port if that's taken; `--port` pins another.

The receiver dials every address found in parallel and runs the handshake on
the first connection that opens. If that handshake fails *before* the receiver
sent its proof (not toss, TLS failure), it moves on to the next connection;
after the proof (any `SentProofError`) it stops, because its single guess may
have been used.

## Secure channel

Over the TCP connection:

1. Plain preamble: receiver sends `TOSS` + version byte, sender answers with its
   own (even on mismatch, so both can explain the problem).
2. TLS 1.3 (stdlib, ALPN `toss/1`). Sender = server with an ephemeral self-signed
   Ed25519 cert; receiver = client with InsecureSkipVerify. Authentication
   comes from the PAKE binding below, not from certificates.
3. `ekm = ExportKeyingMaterial("EXPORTER-toss-pake-v1", nil, 32)`.
4. CPace (ristretto255): receiver = Start, sender = Exchange.
   ContextInfo(idA="toss-receiver", idB="toss-sender", ad = "toss/1" || ekm).
   Binding the PAKE to the TLS exporter defeats a MITM terminating TLS on both
   sides.
5. Key confirmation: HKDF-derived per-role keys; the **receiver sends its MAC
   first**. The sender checks it under a lock (at most one wrong guess is ever
   evaluated, however many connections race), then answers with a status byte
   (ok / wrong code / refused) and, if ok, its own MAC. The sender never reveals
   anything that could confirm a guess before the receiver has committed.
6. A wrong MAC burns the code: that and all later attempts are refused. A
   successful handshake also ends the code (single use). A peer that
   disconnects before sending its MAC has learned nothing and doesn't burn it.

The same "TLS + PAKE-bound exporter" design carries over unchanged to QUIC.

CPace is vendored from `filippo.io/cpace` (BSD, Google LLC) into
`internal/cpace` with its LICENSE and tests. x/crypto/hkdf was swapped for the
stdlib crypto/hkdf and cryptobyte for explicit uint16 length prefixes. The
upstream transcript test vector still passes, so the logic is unchanged.
Deps: github.com/gtank/ristretto255 v0.2.0, filippo.io/edwards25519 v1.2.0.

## Across networks

Package `internal/rendezvous`, using `internal/dht` and quic-go.

- **Meeting.** The sender announces under SHA-1("toss/1 sender " + meetingID),
  the receiver under SHA-1("toss/1 receiver " + meetingID), both with
  `implied_port` so DHT nodes record the NAT's public mapping. Each side polls
  for the other: a full lookup first and every minute, quick re-checks of the
  closest nodes every 2 s.
- **One socket per address family.** The same socket carries the DHT, the
  probes and QUIC, so the mapping the DHT saw is the one QUIC uses. quic-go
  takes KRPC for QUIC packets ("d" sets the QUIC bit), so a small dispatcher
  reads every packet and routes it.
- **Ordering, because of Linux-style routers.** A router that receives the
  peer's packet before its host has sent to that peer creates a conntrack
  entry; the host's own packets to the peer then get another public port,
  and nothing gets through. So:
  1. the receiver's first probes expire after 2 hops: they open its own NAT
     but die before the sender's;
  2. it announces itself only after that;
  3. the sender, finding it, sends at full TTL;
  4. the receiver goes to full TTL (and dials QUIC) once a sender probe
     arrives;
  5. otherwise the TTL climbs 3, 4, ... 16, then full, for carrier-grade NATs
     further up.
- **Symmetric NATs** (several public ports for one socket in DHT replies).
  - The hard side announces port 1 as a marker.
  - Hard sender, easy receiver: the receiver sends 2048 short-TTL guesses at
    random ports on the sender's address *before* announcing itself. The
    sender then sends from 256 sockets (about 99.97% chance that some pair
    meets). It waits 5 s first if its marker went out only just before it
    found the receiver.
  - Easy sender, hard receiver: the receiver sends short-TTL probes from 256
    sockets towards the sender before announcing. The sender then guesses
    1024 ports a round at full TTL, for 4 rounds.
  - Guessing is capped at 2 target addresses per side, so a fake announcement
    can't turn toss into a packet cannon.
  - Two hard NATs: no direct path exists. The receiver says so after 10 s.
- **QUIC.** The receiver dials (TLS client, ALPN `toss/1`). The sender
  listens on its socket(s). The code check runs on the first stream, bound to
  the QUIC TLS exporter, under the same one-guess rule as TCP. A wrong code is
  answered and then the connection is closed gracefully, so that the status
  isn't lost.
- **Tests.**
  - Unit tests use fake DHT nodes on loopback.
  - `scripts/lab` builds namespaces with two routers between two NATs (cone or
    symmetric, plus IPv6 firewalls) and runs real binaries.
  - Results: cone/cone, symmetric/cone and cone/symmetric connect in 1–5 s;
    IPv6 connects when IPv4 is impossible; two symmetric NATs fail clearly.

## Transfer protocol (inside TLS)

Frames: 1-byte type + uint32 big-endian length + payload. Control messages are
JSON (≤ 64 MiB); Data payloads ≤ 1 MiB.

```
sender                                  receiver
Offer {files:[{path,size,exec,mtime}], dirs}  ->
                                        <-  Accept {ok, reason, check:[{i,n}]}
Plan  {hashes:[sha256 of first n bytes]}      ->
                                        <-  Start {from:[{i,n}], skip:[i]}
Data* FileEnd{sha256 of whole file}  (per file, offer order, minus skipped)  ->
                                        <-  Done
```

Either side may send Error (≤ 4 KiB, sanitized before display) and stop. While
data flows, the sender reads from the connection in the background so a
receiver error (disk full, conflict) is reported instead of a broken pipe.

**Resume and skip.** The receiver looks at the destination before asking the
user:
- a `name.toss-part` file of 0 < n ≤ size bytes → resume candidate;
- an existing regular file of exactly the offered size → maybe identical;
- anything else at that path → conflict (unless `--overwrite`, which replaces
  files but never folders).

For candidates it sends `check {i, n}` (sizes only). The sender replies with
the SHA-256 of its own first n bytes and the receiver compares **locally**, so
the sender never learns anything about the receiver's file contents. Matching
partials continue from n (the hash state is kept, so the final full-file hash
still covers everything). Matching existing files are skipped. Mismatched
partials restart from 0. Mismatched existing files are a conflict without
`--overwrite`. Partial names longer than 255 bytes are truncated and get a hash
suffix; offered names ending in `.toss-part` are refused.

**Pipelines.** Sender: read → (hash ‖ encrypt+send). Receiver:
receive+decrypt → (hash ‖ write). The stages share a pool of 1 MiB buffers.
Measured: ~1.5 GB/s over loopback without TLS (the limit is SHA-256 at
1.6 GB/s per core) and ~1.2 GB/s end to end with TLS between two network
namespaces.

## Receiver safety

Found or confirmed by an independent review and by croc's history (its 2023
CVEs: path traversal, terminal escapes, the code in the process list,
overwrites without asking):

- Offers are validated as a whole before anything happens:
  - paths are slash-separated, clean, relative, valid UTF-8 and pass
    `filepath.IsLocal`;
  - they contain no backslash and only visible characters: no control or
    format characters (bidi overrides, zero-width characters), no line
    separators, no private-use or unassigned code points, no blank
    "letters" such as Hangul fillers;
  - no name ends in `.toss-part` in any letter case;
  - on Windows, no reserved names, `<>:"|?*`, or trailing dots or spaces;
  - at most 255 bytes per name, 4096 per path, 128 levels, 1M files;
  - no duplicates (case-insensitively on Windows and macOS), no path that is
    both a file and a folder, total size must not overflow.
- All writes go through `os.Root`, so symlinks in the destination can't
  escape it. Data is written to `name.toss-part`, verified, given the exec bit
  and mtime, then renamed into place. Nothing is overwritten without
  `--overwrite`.
- Free space is checked up front (Linux, macOS, FreeBSD, Windows).
- The prompt always lists what lands directly in the destination (only long
  runs of plain top-level files are shortened). It points out hidden items,
  programs and scripts, and `.ssh` / `.gnupg` / `.git` folders anywhere in
  the offer. It warns when the destination is the home folder. It defaults
  to no, after discarding typed-ahead input. `--yes` refuses offers with
  `.ssh`, `.gnupg` or `.git` (croc refuses those outright; toss lets a person
  decide).
- Automatic refusals (conflicts, no space) look exactly like a person saying
  no, so the sender can't probe which files exist.
- Resuming refuses a partial file that shrank after it was verified, instead
  of zero-padding it.
- Sender side: files are reopened with `O_NOFOLLOW|O_NONBLOCK` and must still
  be the same regular file (same device and inode) as when listed, so a
  symlink or FIFO swapped in by another local user isn't followed.
- Discovery: queries and replies are only accepted from on-link addresses,
  and at most 16 candidate addresses are followed.
- Known gap: macOS treats NFC and NFD spellings of a name as the same file,
  and the standard library has no Unicode normalization. Two such names in
  one offer can't overwrite anything existing (the no-overwrite check happens
  right before the rename), but the second would replace the first.
- Only the executable bit and mtime are taken from the sender. Symlinks and
  special files are skipped on send (a symlink given as an argument is
  followed).

## CLI

- `toss send [--port N] [--code C] PATH...` (TCP 47924 by default, else random)
- `toss send ... [--no-lan]` (don't answer local network searches)
- `toss [receive] [--out DIR] [--yes] [--overwrite] [CODE]`
- `toss version`, `toss help`
- Flags may come before or after arguments; `--` ends flags.
- All UI goes to stderr; the progress line (rate, ETA) is shown on terminals only.

## Lessons from croc

Adopted:
- Strict file names and refusing sensitive folders (from croc v11's
  `receivefs`), with a review prompt instead of a flat refusal.
- Keeping the code out of `ps` (`TOSS_CODE`, a prompt).
- `--overwrite` instead of silent overwriting.
- Local discovery plus a direct-address option (croc's `--ip`).

Later (milestone 4):
- `--text` and stdin/stdout piping.
- `--exclude` and respecting `.gitignore`.
- An upload rate limit.
- `--rename` to receive conflicting files as `name (1).ext`.
- On Windows, mapping names Windows can't store (e.g. containing `:`) to safe
  ones instead of refusing the offer.
- Copying the code to the clipboard.
- Packages for winget, scoop, Homebrew and AUR.

Skipped on purpose:
- Compression by default: it's slower than the network on a LAN, and most
  large files are already compressed.
- An update check that calls GitHub: that's a third party. Re-running the
  installer updates instead.
- Relays, proxies, stored uploads, Tailscale/DERP transport.

## Milestones

1. **Same network + direct address, with resume.** Done.
1b. **Different networks, one code.** Done. Details in "Across networks"
   below.
2. Router port opening: UPnP IGD, NAT-PMP, PCP (written in-repo).
3. **Router-to-router**: BitTorrent mainline DHT (minimal in-repo KRPC client;
   announce under H(meetingID); DHT responses' `ip` field gives our public
   address, no STUN needed) + UDP hole punching + QUIC (`quic-go`, agreed) using
   the same TLS+PAKE binding. Revisit collisions on the meeting ID (allow a few
   failed PAKE attempts, or lengthen the meeting ID).
4. Parallel streams over high-latency links, text/stdin sending.
5. Optional `toss ui`: local web UI served by the toss binary on localhost.

## Browser version (not planned yet)

A pure website can't satisfy "no servers":
- browsers can't open raw TCP/UDP, join the DHT, or do LAN discovery;
- their only P2P is WebRTC, which needs a signaling server (plus usually STUN)
  to meet.

Options:
- `toss ui` (local web UI, the binary does the networking): fully consistent
  with the design. Preferred; to be thought about after the core is solid.
- Hosted website using WebRTC + a tiny signaling server (no file data through
  it). Breaks "no servers"; CLI interop would need WebRTC (pion) in toss,
  which is many dependencies. Separate decision.

## Distribution

- `scripts/dist.sh VERSION` cross-compiles static, `-trimpath` binaries for
  linux (amd64, arm64, arm, 386), windows (amd64, arm64), darwin (amd64,
  arm64) and freebsd/amd64. The archives are reproducible (timestamps from
  the commit) and come with `SHA256SUMS`.
- `.github/workflows/release.yml` runs on tags `v*`:
  - the full CI first: tests on Linux, Windows and macOS, plus real runs of
    both installers;
  - then the build (without the Go module cache), a build provenance
    attestation, and `gh release create`.

  Actions are pinned by commit SHA.
- `install.sh` (sh/dash/busybox) and `install.ps1` (Windows PowerShell 5.1
  and PowerShell 7) download the right archive, verify it against
  `SHA256SUMS`, install without admin rights, and add the folder to PATH (on
  Windows, editing the registry value without expanding existing entries).

## Decisions

- License: MIT.
- QUIC via quic-go for milestone 3.
