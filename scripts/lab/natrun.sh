#!/bin/sh
# Send a file between the two hosts of the NAT lab and check it arrived.
#
#   sudo scripts/lab/natlab.sh up symmetric cone      # build the lab
#   sudo scripts/lab/natrun.sh FILE                   # sender in A, receiver in B
#   sudo RECEIVER_FIRST=1 scripts/lab/natrun.sh FILE  # receiver starts 8 s early
#   sudo V6=1 scripts/lab/natrun.sh FILE              # lab built with V6=1
#
# The hosts only meet through fake DHT nodes in the lab; nothing leaves it.
set -u
[ $# -eq 1 ] || { echo "usage: natrun.sh FILE" >&2; exit 2; }
file=$(realpath "$1")
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(cd "$repo" && go build -o "$work/toss" ./cmd/toss && go test -c -o "$work/dht.test" ./internal/dht) || exit 1
cd "$work"

DHT=$(seq -s, -f '203.0.113.100:%g' 6881 6888)
BOOT=203.0.113.100:6881
if [ -n "${V6:-}" ]; then
	DHT="$DHT,$(seq -s, -f '[3fff:1::100]:%g' 6881 6888)"
	BOOT="$BOOT,[3fff:1::100]:6881"
fi
ip netns exec labdht env TOSS_FAKE_DHT="$DHT" ./dht.test -test.run TestServeFakeDHT >dht.log 2>&1 &
DPID=$!
sleep 0.5
export TOSS_DEBUG=1 TOSS_DHT_BOOTSTRAP="$BOOT" HOME="$work/home" XDG_CACHE_HOME="$work/home/.cache"
mkdir -p home
code=1234-acid-acorn-acre
start=$(date +%s%N)
if [ -n "${RECEIVER_FIRST:-}" ]; then
	timeout 100 ip netns exec labhostB ./toss "$code" --out out --yes >recv.log 2>&1 &
	RPID=$!
	sleep 8
	ip netns exec labhostA ./toss send --code "$code" "$file" >send.log 2>&1 &
	SPID=$!
	wait $RPID
	rc=$?
else
	ip netns exec labhostA ./toss send --code "$code" "$file" >send.log 2>&1 &
	SPID=$!
	sleep 1
	start=$(date +%s%N)
	timeout 100 ip netns exec labhostB ./toss "$code" --out out --yes >recv.log 2>&1
	rc=$?
fi
end=$(date +%s%N)
kill $SPID 2>/dev/null
kill -INT $DPID 2>/dev/null
wait 2>/dev/null
if [ $rc -eq 0 ] && cmp -s "$file" "out/$(basename "$file")"; then
	echo "OK: arrived intact after $(( (end - start) / 1000000 )) ms"
	exit 0
fi
echo "FAILED (receiver exit $rc after $(( (end - start) / 1000000 )) ms)"
echo "--- receiver:"; tr '\r' '\n' <recv.log | grep -v '^  .*%'
echo "--- sender:"; tr '\r' '\n' <send.log | grep -v '^  .*%'
exit 1
