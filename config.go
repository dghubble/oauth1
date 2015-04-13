package oauth1

import (
	"net/http"
)

// Config stores consumer/client credentials.
type Config struct {
	// Application client
	ConsumerKey string
	// Application secret
	ConsumerSecret string
}

func NewConfig(consumerKey, consumerSecret string) *Config {
	return &Config{
		ConsumerKey:    consumerKey,
		ConsumerSecret: consumerSecret,
	}
}

// Client returns an HTTP client which uses the provided Token.
func (c *Config) Client(t *Token) *http.Client {
	return NewClient(c, t)
}

// Returns a new http Client which signs requests via OAuth1.
func NewClient(config *Config, token *Token) *http.Client {
	transport := &Transport{
		source: &ReuseTokenSource{token, nil},
		signer: &Signer{config},
	}
	return &http.Client{Transport: transport}
}
