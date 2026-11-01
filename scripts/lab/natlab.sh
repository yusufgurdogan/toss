#!/bin/sh
# NAT lab: two home networks behind NAT routers, a small "internet"
# between them (two routers) and fake DHT nodes. Needs root, ip and nft;
# it only creates network namespaces named lab*.
#
#   hostA -- natA ==S1(203.0.113.0/24)== r1 ---- r2 ==S2(198.51.100.0/24)== natB -- hostB
#                         |
#                        dht (203.0.113.100, fake DHT nodes)
#
#   natlab.sh up [cone|symmetric] [cone|symmetric]    NAT type for A and B
#   natlab.sh down
set -eu
NS="labs1 labr1 labr2 labnatA labhostA labnatB labhostB labdht"
down() { for n in $NS; do ip netns del $n 2>/dev/null || true; done; }
if [ "${1:-}" = down ]; then down; exit 0; fi
typeA=${2:-cone}; typeB=${3:-cone}
down
for n in $NS; do
	ip netns add $n
	ip -n $n link set lo up
	if [ -n "${V6:-}" ]; then
		ip netns exec $n sh -c 'echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6; echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
	else
		ip netns exec $n sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
	fi
	ip netns exec $n sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
done
# link <nsA> <ifA> <ipA/len> <nsB> <ifB> <ipB/len>   (ip "-" = none)
N=0
link() {
	# Unique temporary names: udev may derive MAC addresses from them.
	N=$((N+1)); a="lk$N-$$a"; b="lk$N-$$b"
	ip link add "$a" type veth peer name "$b"
	ip link set "$a" netns "$1"; ip -n "$1" link set "$a" name "$2"
	ip link set "$b" netns "$4"; ip -n "$4" link set "$b" name "$5"
	[ "$3" != - ] && ip -n "$1" addr add "$3" dev "$2"
	[ "$6" != - ] && ip -n "$4" addr add "$6" dev "$5"
	ip -n "$1" link set "$2" up; ip -n "$4" link set "$5" up
}
ip -n labs1 link add br0 type bridge; ip -n labs1 link set br0 up
link labnatA wan 203.0.113.10/24 labs1 pA -
link labr1 s1 203.0.113.1/24 labs1 pR -
link labdht eth0 203.0.113.100/24 labs1 pD -
for p in pA pR pD; do ip -n labs1 link set $p master br0; done
link labr1 r12 10.99.12.1/24 labr2 r21 10.99.12.2/24
link labr2 s2 198.51.100.1/24 labnatB wan 198.51.100.20/24
link labnatA lan 10.1.0.1/24 labhostA eth0 10.1.0.2/24
link labnatB lan 10.2.0.1/24 labhostB eth0 10.2.0.2/24
ip -n labnatA route add default via 203.0.113.1
ip -n labdht route add default via 203.0.113.1
ip -n labr1 route add 198.51.100.0/24 via 10.99.12.2
ip -n labr2 route add 203.0.113.0/24 via 10.99.12.1
ip -n labnatB route add default via 198.51.100.1
ip -n labhostA route add default via 10.1.0.1
ip -n labhostB route add default via 10.2.0.1
nat() { # nat <ns> cone|symmetric
	flag=""
	[ "$2" = symmetric ] && flag="fully-random"
	ip netns exec "$1" nft -f - <<NFT
table ip nat {
	chain post {
		type nat hook postrouting priority 100;
		oifname "wan" masquerade $flag
	}
}
NFT
}
nat labnatA "$typeA"
nat labnatB "$typeB"
if [ -n "${V6:-}" ]; then
	# IPv6 (3fff::/20 is reserved for documentation): no NAT, but the home
	# routers drop unsolicited incoming traffic, like real ones.
	a6() { ip -n "$1" addr add "$3" dev "$2" nodad; }
	a6 labnatA wan 3fff:1::10/64; a6 labr1 s1 3fff:1::1/64; a6 labdht eth0 3fff:1::100/64
	a6 labr1 r12 3fff:12::1/64; a6 labr2 r21 3fff:12::2/64
	a6 labr2 s2 3fff:2::1/64; a6 labnatB wan 3fff:2::20/64
	a6 labnatA lan 3fff:a::1/64; a6 labhostA eth0 3fff:a::2/64
	a6 labnatB lan 3fff:b::1/64; a6 labhostB eth0 3fff:b::2/64
	ip -n labnatA -6 route add default via 3fff:1::1
	ip -n labdht -6 route add default via 3fff:1::1
	ip -n labr1 -6 route add 3fff:2::/64 via 3fff:12::2
	ip -n labr1 -6 route add 3fff:b::/64 via 3fff:12::2
	ip -n labr1 -6 route add 3fff:a::/64 via 3fff:1::10
	ip -n labr2 -6 route add 3fff:1::/64 via 3fff:12::1
	ip -n labr2 -6 route add 3fff:a::/64 via 3fff:12::1
	ip -n labr2 -6 route add 3fff:b::/64 via 3fff:2::20
	ip -n labnatB -6 route add default via 3fff:2::1
	ip -n labhostA -6 route add default via 3fff:a::1
	ip -n labhostB -6 route add default via 3fff:b::1
	for n in labnatA labnatB; do
		ip netns exec $n nft -f - <<NFT
table ip6 fw {
	chain filter_forward {
		type filter hook forward priority 0; policy accept;
		iifname "wan" ct state established,related accept
		iifname "wan" drop
	}
}
NFT
	done
fi
echo "lab up: A behind $typeA NAT, B behind $typeB NAT${V6:+, IPv6 with firewalls}"
