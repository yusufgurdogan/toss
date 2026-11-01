package dht

import (
	"os"
	"path/filepath"
)

// The node cache keeps DHT nodes that answered in earlier runs, so later
// runs can join the network without the bootstrap routers.

// CacheDir is where node caches are kept; empty disables caching. Tests
// clear it.
var CacheDir = func() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "toss")
}()

const maxCached = 256

func cacheFile(v6 bool) string {
	if CacheDir == "" {
		return ""
	}
	if v6 {
		return filepath.Join(CacheDir, "dht6.nodes")
	}
	return filepath.Join(CacheDir, "dht4.nodes")
}

func entrySize(v6 bool) int {
	if v6 {
		return 38
	}
	return 26
}

func loadCache(v6 bool) []Node {
	name := cacheFile(v6)
	if name == "" {
		return nil
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return nil
	}
	size := entrySize(v6)
	var out []Node
	for len(b) >= size && len(out) < maxCached {
		var n Node
		copy(n.ID[:], b[:20])
		if a, ok := parseCompactAddr(string(b[20:size])); ok {
			n.Addr = a
			out = append(out, n)
		}
		b = b[size:]
	}
	return out
}

func saveCache(v6 bool, nodes []Node) {
	name := cacheFile(v6)
	if name == "" || len(nodes) == 0 {
		return
	}
	var b []byte
	for i, n := range nodes {
		if i == maxCached {
			break
		}
		b = append(b, n.ID[:]...)
		b = append(b, compactAddr(n.Addr)...)
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return
	}
	tmp := name + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, name)
	}
}
