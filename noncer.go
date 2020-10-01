package oauth1

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// Noncer provides random nonce strings.
type Noncer interface {
	Nonce() string
}

// NoncerFunc is an adapter to allow the use of
// ordinary functions as Noncers. If f is a function
// with the appropriate signature, NoncerFunc(f) is a
// Noncer that calls f.
type NoncerFunc func() string

// Nonce calls f().
func (f NoncerFunc) Nonce() string {
	return f()
}

var (
	// DefaultNoncer is the default Noncer. It reads 32
	// bytes from crypto/rand and returns those bytes as a
	// base64 encoded string.
	DefaultNoncer Noncer = NoncerFunc(func() string {
		b := make([]byte, 32)
		rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	})

	// HexNoncer reads 16 bytes from crypto/rand and returns
	// those bytes as a hex encoded string.
	HexNoncer Noncer = NoncerFunc(func() string {
		b := make([]byte, 16)
		rand.Read(b)
		return hex.EncodeToString(b)
	})
)
