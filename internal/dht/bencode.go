package dht

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// A minimal bencode codec, enough for KRPC. Decoded values are int64,
// string (byte strings, binary safe), []any and map[string]any.

const maxDepth = 16

var errBencode = errors.New("dht: malformed bencode")

func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := encodeTo(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func encodeTo(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case int:
		fmt.Fprintf(b, "i%de", x)
	case int64:
		fmt.Fprintf(b, "i%de", x)
	case string:
		fmt.Fprintf(b, "%d:%s", len(x), x)
	case []byte:
		fmt.Fprintf(b, "%d:", len(x))
		b.Write(x)
	case []any:
		b.WriteByte('l')
		for _, e := range x {
			if err := encodeTo(b, e); err != nil {
				return err
			}
		}
		b.WriteByte('e')
	case []string:
		b.WriteByte('l')
		for _, e := range x {
			fmt.Fprintf(b, "%d:%s", len(e), e)
		}
		b.WriteByte('e')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('d')
		for _, k := range keys {
			fmt.Fprintf(b, "%d:%s", len(k), k)
			if err := encodeTo(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('e')
	default:
		return fmt.Errorf("dht: can't bencode %T", v)
	}
	return nil
}

// decode parses exactly one bencoded value that must span all of data.
func decode(data []byte) (any, error) {
	v, rest, err := decodeValue(data, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errBencode
	}
	return v, nil
}

func decodeValue(data []byte, depth int) (any, []byte, error) {
	if len(data) == 0 || depth > maxDepth {
		return nil, nil, errBencode
	}
	switch c := data[0]; {
	case c == 'i':
		end := bytes.IndexByte(data, 'e')
		if end < 2 {
			return nil, nil, errBencode
		}
		n, err := strconv.ParseInt(string(data[1:end]), 10, 64)
		if err != nil {
			return nil, nil, errBencode
		}
		return n, data[end+1:], nil
	case c >= '0' && c <= '9':
		colon := bytes.IndexByte(data, ':')
		if colon < 1 || colon > 10 {
			return nil, nil, errBencode
		}
		n, err := strconv.Atoi(string(data[:colon]))
		if err != nil || n < 0 || n > len(data)-colon-1 {
			return nil, nil, errBencode
		}
		start := colon + 1
		return string(data[start : start+n]), data[start+n:], nil
	case c == 'l':
		var list []any
		data = data[1:]
		for len(data) > 0 && data[0] != 'e' {
			v, rest, err := decodeValue(data, depth+1)
			if err != nil {
				return nil, nil, err
			}
			list = append(list, v)
			data = rest
		}
		if len(data) == 0 {
			return nil, nil, errBencode
		}
		return list, data[1:], nil
	case c == 'd':
		dict := map[string]any{}
		data = data[1:]
		for len(data) > 0 && data[0] != 'e' {
			k, rest, err := decodeValue(data, depth+1)
			if err != nil {
				return nil, nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, nil, errBencode
			}
			v, rest, err := decodeValue(rest, depth+1)
			if err != nil {
				return nil, nil, err
			}
			dict[key] = v
			data = rest
		}
		if len(data) == 0 {
			return nil, nil, errBencode
		}
		return dict, data[1:], nil
	}
	return nil, nil, errBencode
}

// IsKRPC reports whether a UDP payload looks like a KRPC message, so a
// socket shared with other protocols can route it here.
func IsKRPC(b []byte) bool {
	return len(b) > 8 && b[0] == 'd' && b[len(b)-1] == 'e' && bytes.Contains(b, []byte("1:y1:"))
}
