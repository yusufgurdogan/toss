# Security

toss is meant to be safe to use with someone on the same network who might
be hostile. If you find a way to:

- read or change a transfer without the code,
- get more than one guess at a code,
- make a receiver write outside its destination folder, overwrite a file
  without `--overwrite`, or run code,
- learn something about the receiver's files that the receiver didn't
  agree to share,

please report it privately through GitHub's
[private vulnerability reporting](https://github.com/yusufgurdogan/toss/security/advisories/new)
rather than in a public issue. Include the toss version (`toss version`) and
steps to reproduce.

The threat model and the known limitations are described in
[DESIGN.md](DESIGN.md) and in the Security section of the
[README](README.md).
