#!/bin/sh
# Install toss on Linux, macOS or FreeBSD:
#
#   curl -fsSL https://raw.githubusercontent.com/yusufgurdogan/toss/main/install.sh | sh
#
# Run it again to update. Settings (environment variables):
#   TOSS_VERSION      release to install, e.g. v0.1.0 (default: latest)
#   TOSS_INSTALL_DIR  where to put the binary (default: /usr/local/bin as
#                     root, otherwise ~/.local/bin)
#
# The archive is checked against the release's SHA256SUMS before anything
# is installed.
set -eu

repo=yusufgurdogan/toss

main() {
	need uname
	need tar
	need mktemp

	os=$(uname -s)
	case $os in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	FreeBSD) os=freebsd ;;
	*) fail "unsupported system $os (on Windows, use install.ps1)" ;;
	esac

	arch=$(uname -m)
	case $arch in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	armv6* | armv7* | armv8l | arm) arch=arm ;;
	i386 | i486 | i586 | i686) arch=386 ;;
	*) fail "unsupported processor $arch" ;;
	esac
	# A 64-bit macOS kernel can report x86_64 under Rosetta; prefer native.
	if [ "$os" = darwin ] && [ "$arch" = amd64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
		arch=arm64
	fi
	case "$os/$arch" in
	linux/* | darwin/amd64 | darwin/arm64 | freebsd/amd64) ;;
	*) fail "no prebuilt toss for $os/$arch; build it with: go install github.com/$repo/cmd/toss@latest" ;;
	esac

	version=${TOSS_VERSION:-latest}
	proto='=https'
	if [ -n "${TOSS_BASE_URL:-}" ]; then # a mirror, or a local test server
		base=${TOSS_BASE_URL%/}
		proto='=http,https'
	elif [ "$version" = latest ]; then
		base=https://github.com/$repo/releases/latest/download
	else
		base=https://github.com/$repo/releases/download/$version
	fi

	if [ -n "${TOSS_INSTALL_DIR:-}" ]; then
		dir=$TOSS_INSTALL_DIR
	elif [ "$(id -u)" = 0 ]; then
		dir=/usr/local/bin
	elif [ -n "${PREFIX:-}" ] && [ -d "$PREFIX/bin" ] && [ -w "$PREFIX/bin" ]; then
		dir=$PREFIX/bin # Termux
	else
		dir=$HOME/.local/bin
	fi

	archive=toss_${os}_${arch}.tar.gz
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM

	say "Downloading toss ($version, $os/$arch)..."
	download "$base/$archive" "$tmp/$archive"
	download "$base/SHA256SUMS" "$tmp/SHA256SUMS"

	want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
	[ -n "$want" ] || fail "$archive is not listed in SHA256SUMS"
	got=$(sha256 "$tmp/$archive")
	[ "$got" = "$want" ] || fail "checksum mismatch for $archive (got $got, want $want); not installing"

	tar -xzf "$tmp/$archive" -C "$tmp" toss
	mkdir -p "$dir" || fail "can't create $dir (set TOSS_INSTALL_DIR, or run with sudo for /usr/local/bin)"
	# Install atomically, so a running toss is never left half-written.
	cp "$tmp/toss" "$dir/.toss.new" || fail "can't write to $dir (set TOSS_INSTALL_DIR, or run with sudo)"
	chmod 755 "$dir/.toss.new"
	mv -f "$dir/.toss.new" "$dir/toss"

	say "Installed $("$dir/toss" version) to $dir/toss"
	case ":$PATH:" in
	*":$dir:"*) say "Run 'toss help' to get started." ;;
	*)
		say ""
		say "$dir is not in your PATH. Add this line to your shell profile"
		say "(~/.profile, ~/.bashrc or ~/.zshrc), then open a new terminal:"
		say ""
		say "    export PATH=\"$dir:\$PATH\""
		;;
	esac
}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto "$proto" --tlsv1.2 --retry 3 -o "$2" "$1" || fail "download failed: $1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1" || fail "download failed: $1"
	else
		fail "need curl or wget"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif command -v sha256 >/dev/null 2>&1; then
		sha256 -q "$1"
	else
		fail "need sha256sum, shasum or sha256 to verify the download"
	fi
}

need() { command -v "$1" >/dev/null 2>&1 || fail "need $1"; }
say() { printf '%s\n' "$*"; }
fail() {
	printf 'toss install: %s\n' "$*" >&2
	exit 1
}

main "$@"
