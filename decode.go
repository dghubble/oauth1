package oauth1

import (
	"net/url"
	"strings"
)

// PercentDecode percent-decodes a string according to RFC 5849 3.6.
// https://datatracker.ietf.org/doc/html/rfc5849#section-3.6
// In summary, only decode %XX
//
// Modified from url.unescape
func PercentDecode(input string) (string, error) {
	// Count %, check that they're well-formed.
	n := 0
	for i := 0; i < len(input); {
		switch input[i] {
		case '%':
			n++
			if i+2 >= len(input) || !ishex(input[i+1]) || !ishex(input[i+2]) {
				input = input[i:]
				if len(input) > 3 {
					input = input[:3]
				}
				return "", url.EscapeError(input)
			}
			i += 3
		default:
			i++
		}
	}

	if n == 0 {
		return input, nil
	}

	var t strings.Builder
	t.Grow(len(input) - 2*n)
	for i := 0; i < len(input); i++ {
		switch input[i] {
		case '%':
			t.WriteByte(unhex(input[i+1])<<4 | unhex(input[i+2]))
			i += 2
		default:
			t.WriteByte(input[i])
		}
	}
	return t.String(), nil
}

// ishex is copied from url package
func ishex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	// https://datatracker.ietf.org/doc/html/rfc5849#section-3.6
	// The two hexadecimal characters used to represent encoded	characters MUST be uppercase.
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

// unhex is copied from url package
func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	// https://datatracker.ietf.org/doc/html/rfc5849#section-3.6
	// The two hexadecimal characters used to represent encoded	characters MUST be uppercase.
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
