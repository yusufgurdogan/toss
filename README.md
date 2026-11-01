# toss

Send files directly from one computer to another. End-to-end encrypted, no
servers, no relays, no accounts: the data goes straight between the two
machines.

```
$ toss send photos/ notes.txt
Sending 121 files, 1.2 GB.

On the other computer, run:

    toss 7392-river-moon-sun

Waiting for the receiver... (Ctrl-C to cancel)
```

```
$ toss 7392-river-moon-sun
Looking for the sender on this network...
Connected to 192.168.1.20:41234.
The sender offers 121 files, 1.2 GB:
  photos/  (120 files, 1.2 GB)
  notes.txt  (12.0 kB)
into /home/you/Downloads
Receive? [Y/n]
   48%  580.1 MB of 1.2 GB  112.3 MB/s  0:05 left
```

## Install

**Linux, macOS, FreeBSD:**

```
curl -fsSL https://raw.githubusercontent.com/yusufgurdogan/toss/main/install.sh | sh
```

**Windows** (PowerShell, no admin rights needed):

```
irm https://raw.githubusercontent.com/yusufgurdogan/toss/main/install.ps1 | iex
```

Both download the right binary for your machine from the latest
[release](https://github.com/yusufgurdogan/toss/releases), check it against
the release's `SHA256SUMS`, install it (to `~/.local/bin`, `/usr/local/bin`
when run as root, or `%LOCALAPPDATA%\Programs\toss` on Windows) and make sure
it's on your PATH. Run the same command again to update.

You can also download an archive from the releases page and put `toss` (or
`toss.exe`) anywhere on your PATH. With Go 1.26 or newer you can build it
yourself:

```
go install github.com/yusufgurdogan/toss/cmd/toss@latest
```

Release binaries are built by GitHub Actions from the tagged source, with a
signed build provenance attestation you can check:

```
gh attestation verify toss_linux_amd64.tar.gz --repo yusufgurdogan/toss
```

## Usage

```
toss send [options] FILE|FOLDER...   send files and print a code
toss [receive] [options] [CODE]      receive files (asks for the code if not given)
toss version
```

Send options:

- `--code CODE`: use this code instead of a random one
- `--port N`: listen on TCP port N (default: 47924, or any free port if that's
  taken)
- `--no-lan`: don't answer local network searches (e.g. on public Wi-Fi); the
  code then includes this computer's address

Receive options:

- `--out DIR`: save into DIR (default: the current folder)
- `--yes`, `-y`: accept without asking
- `--overwrite`: replace existing files that are different

On a shared computer, pass the code in the `TOSS_CODE` environment variable
(or type it at the prompt) so it doesn't show up in the process list.

## Where it works

Anywhere the two computers can reach the internet, with the same one code:

- **Same network:** found instantly on the local network.
- **Different networks:** both sides meet through the BitTorrent DHT (the
  same worldwide, ownerless network torrent clients use) and open a direct
  connection through their routers with UDP hole punching, then transfer
  over QUIC. This works behind typical home routers and on servers whose
  incoming ports are closed.
- **Stricter networks too:** when one side is behind a "symmetric" NAT
  (some office firewalls, cloud NAT gateways, mobile carriers), toss finds a
  way through by trying many ports at once. Over IPv6, which most mobile
  networks offer, there's usually no NAT at all.
- **Two symmetric NATs facing each other can't be connected directly.**
  toss never relays your data through anyone else's server, so in that case
  it says so (within seconds) and suggests what helps, such as putting one
  computer on another network.
- If you know the sender's address and port is open, you can also skip the
  search: `toss 7392-river-moon-sun@203.0.113.5:47924`.

### Firewalls

- **Windows** asks the first time you run `toss send` whether toss may use
  the network. Allow it for private networks.
- **Linux** with a firewall that blocks incoming traffic (for example after
  `ufw enable`): the sender listens on TCP port 47924 when it's free, so
  allow that once with `sudo ufw allow 47924/tcp`. The automatic search also
  needs incoming UDP (port 47923 on the sender, and the replies on the
  receiver). If a firewall gets in its way, add the sender's address to the
  code (`CODE@ADDRESS:47924`): that only needs the sender's TCP port.

## Resuming

If a transfer stops (Ctrl-C, network drop, laptop closed), run the same
`toss send` again and receive into the same folder. The receiver keeps what
arrived in `name.toss-part` files and toss transfers only what is missing.
Files that are already there and identical are skipped. Before reusing
anything, toss checks that the bytes on both sides match.

## Security

- **Encryption.** Everything after the first five bytes runs inside TLS 1.3
  (with the hybrid post-quantum key exchange Go uses by default).
- **Authentication.** The code is the password for a PAKE (CPace on
  ristretto255) run inside TLS and bound to the TLS session. Someone in the
  middle can't decrypt or alter the transfer without knowing the code, and
  watching the exchange tells them nothing about the code.
- **One guess.** The first part of the code (`7392-river`) is used to find
  each other and is not secret. The remaining words are, and an attacker gets
  exactly one online guess at them: about a 1 in 1.7 million chance. After a
  wrong guess the sender stops and the code is dead.
- **Integrity.** Every file is checked with SHA-256 end to end before it's put
  in place.
- **Safe receiving.**
  - The receiver shows what's coming and asks first; the answer defaults to
    no.
  - Folders, hidden items, programs and scripts, and folders that can hold
    keys or run code (`.ssh`, `.gnupg`, `.git`) are always pointed out.
    `--yes` won't accept the last kind without a person looking.
  - Files can only be written inside the destination folder (enforced with
    `os.Root`, so symlinks can't escape it).
  - Names with `..`, absolute paths, invisible or control characters, or
    other tricks are refused.
  - Nothing is overwritten unless you pass `--overwrite`, and folders are
    never replaced.
  - Only the executable bit and modification time are copied from the
    sender. Symbolic links are not sent.
  - A refusal looks the same to the sender whatever the reason, so it can't
    probe which files you have.
- **What the network can see.** The two IP addresses, the timing, and roughly
  how much data moved. File names, sizes and contents are encrypted. On the
  local network, the receiver's search packets name the public part of the
  code. The DHT nodes both sides talk to see their public IP addresses and a
  hash of the code's public part; nothing secret goes through the DHT.

## How it works

1. **Finding each other.** Every way is tried at once:
   - the local network: UDP port 47923, multicast 239.255.116.115, IPv6
     ff02::746f:7373 and broadcast;
   - the BitTorrent DHT, under hashes of the code's public part (`7392-river`);
   - a `code@address` if given.

   Across networks, each side learns the other's public address from the
   DHT. Both then send UDP probes to each other so their routers let the
   other side in (hole punching); the first probes are ordered and
   short-lived so routers don't block each other. Behind symmetric NATs, many
   ports are tried at once.
2. **Checking the code.** Over TCP (local network) or QUIC (internet) the two
   sides run TLS 1.3, then CPace with the full code, using the TLS exporter as
   associated data, then confirm they derived the same key.
3. The sender offers its file list. The receiver checks it against the
   destination folder and asks you. For resuming, it asks the sender for
   hashes of what it already has.
4. The files stream through a pipeline that reads, hashes, encrypts and
   writes in parallel: about 1.2 GB/s over a local network, and about
   1 Gbit/s over QUIC.

Set `TOSS_DEBUG=1` to see what the search is doing. `scripts/lab/` holds a
NAT simulation (Linux network namespaces, needs root) that runs real toss
binaries through cone and symmetric NATs and IPv6 firewalls.

Details are in [DESIGN.md](DESIGN.md).

## Dependencies

The Go standard library, plus `github.com/gtank/ristretto255` and
`filippo.io/edwards25519` for the PAKE group, and `github.com/quic-go/quic-go`
(which brings the Go team's `golang.org/x/crypto`, `x/net` and `x/sys`) for
QUIC. The DHT client and everything else is in this repository. The CPace implementation is
vendored from `filippo.io/cpace` (BSD, Google LLC) in `internal/cpace`.

## License

MIT. The word list in `internal/code/words.txt` is the EFF Short Wordlist
(CC BY 3.0 US); see `internal/code/WORDLIST-NOTICE`.
