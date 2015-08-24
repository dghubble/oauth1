package oauth1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewToken(t *testing.T) {
	expectedToken := "token"
	expectedSecret := "secret"
	tk := NewToken(expectedToken, expectedSecret)
	assert.Equal(t, expectedToken, tk.Token)
	assert.Equal(t, expectedSecret, tk.TokenSecret)
}
