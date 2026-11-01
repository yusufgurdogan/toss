#!/bin/sh
# Build release archives for every supported platform into dist/, plus
# SHA256SUMS. Builds are reproducible: static, -trimpath, and archive
# timestamps taken from the last commit.
#
#   scripts/dist.sh v0.1.0
set -eu

version=${1:?usage: scripts/dist.sh VERSION}
cd "$(dirname "$0")/.."

: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH CGO_ENABLED=0 GOFLAGS=-mod=readonly

targets="linux/amd64 linux/arm64 linux/arm linux/386
windows/amd64 windows/arm64
darwin/amd64 darwin/arm64
freebsd/amd64"

rm -rf dist
mkdir -p dist

for target in $targets; do
	os=${target%/*}
	arch=${target#*/}
	name=toss_${os}_${arch}
	dir=dist/$name
	exe=toss
	[ "$os" = windows ] && exe=toss.exe
	mkdir -p "$dir"

	# GOARM=6 makes the 32-bit ARM build run on every Raspberry Pi.
	GOOS=$os GOARCH=$arch GOARM=6 go build -trimpath \
		-ldflags "-s -w -X main.version=$version" -o "$dir/$exe" ./cmd/toss
	cp LICENSE README.md "$dir/"
	touch -d "@$SOURCE_DATE_EPOCH" "$dir/$exe" "$dir/LICENSE" "$dir/README.md"

	if [ "$os" = windows ]; then
		if command -v zip >/dev/null 2>&1; then
			(cd "$dir" && zip -q -X -D "../$name.zip" "$exe" LICENSE README.md)
		else
			python3 - "$dir" "dist/$name.zip" "$exe" LICENSE README.md <<'PY'
import os, sys, time, zipfile
src, out, names = sys.argv[1], sys.argv[2], sys.argv[3:]
stamp = time.gmtime(int(os.environ["SOURCE_DATE_EPOCH"]))[:6]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for n in names:
        info = zipfile.ZipInfo(n, stamp)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        with open(os.path.join(src, n), "rb") as f:
            z.writestr(info, f.read())
PY
		fi
	else
		tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
			-C "$dir" -cf - "$exe" LICENSE README.md | gzip -n -9 >"dist/$name.tar.gz"
	fi
	rm -rf "$dir"
done

(cd dist && sha256sum toss_* >SHA256SUMS)
cat dist/SHA256SUMS
