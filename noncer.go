package oauth1

import (
	"crypto/rand"
	"encoding/base64"
)

// A Noncer generates random string.
type Noncer interface {
	// returns random string
	Nonce() string
}

// DefaultNoncer generates base64 encoded random string.
type DefaultNoncer struct {
	nonce string
}

// Nonce returns a base64 encoded random 32 byte string.
func (s *DefaultNoncer) Nonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
