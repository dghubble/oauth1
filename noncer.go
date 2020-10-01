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
	DefaultNoncer Noncer = Base64Noncer{
		Length: 32,
	}
)

// Base64Noncer reads Length bytes from crypto/rand and
// returns those bytes as a base64 encoded string. If
// Length is 0, 32 bytes are read.
type Base64Noncer struct {
	Length int
}

// Nonce provides a random nonce string.
func (n Base64Noncer) Nonce() string {
	length := n.Length
	if length == 0 {
		length = 32
	}
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// HexNoncer reads Length bytes from crypto/rand and
// returns those bytes as a base64 encoded string. If
// Length is 0, 32 bytes are read.
type HexNoncer struct {
	Length int
}

// Nonce provides a random nonce string.
func (n HexNoncer) Nonce() string {
	length := n.Length
	if length == 0 {
		length = 32
	}
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}
