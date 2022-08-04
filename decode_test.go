package oauth1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPercentDecode(t *testing.T) {
	// copied from TestPercentEncode
	cases := []struct {
		expected string
		input    string
	}{
		{" ", "%20"},
		{"%", "%25"},
		{"&", "%26"},
		{"-._", "-._"},
		{" /=+", "%20%2F%3D%2B"},
		{"Ladies + Gentlemen", "Ladies%20%2B%20Gentlemen"},
		{"An encoded string!", "An%20encoded%20string%21"},
		{"Dogs, Cats & Mice", "Dogs%2C%20Cats%20%26%20Mice"},
		{"☃", "%E2%98%83"},
	}
	for _, c := range cases {
		output, err := PercentDecode(c.input)
		require.NoError(t, err)
		if output != c.expected {
			t.Errorf("expected %s, got %s", c.expected, output)
		}
	}
}

func TestPercentDecode_InvalidPercent(t *testing.T) {
	for _, c := range []string{"%2", "%%%%"} {
		output, err := PercentDecode(c)
		require.Error(t, err, output)
	}
}
