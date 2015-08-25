package oauth1

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTransport(t *testing.T) {
	const (
		expectedToken       = "some_token"
		expectedConsumerKey = "consumer_key"
		expectedNonce       = "some_nonce"
		expectedTimestamp   = "123456789"
	)
	server := newMockServer(func(w http.ResponseWriter, req *http.Request) {
		params := parseOAuthParamsOrFail(t, req.Header.Get("Authorization"))
		assert.Equal(t, expectedToken, params[oauthTokenParam])
		assert.Equal(t, expectedConsumerKey, params[oauthConsumerKeyParam])
		assert.Equal(t, expectedNonce, params[oauthNonceParam])
		assert.Equal(t, defaultSignatureMethod, params[oauthSignatureMethodParam])
		assert.Equal(t, expectedTimestamp, params[oauthTimestampParam])
		assert.Equal(t, defaultOauthVersion, params[oauthVersionParam])
		// oauth_signature will vary, httptest.Server uses a random port
	})
	defer server.Close()

	config := &Config{
		ConsumerKey:    expectedConsumerKey,
		ConsumerSecret: "consumer_secret",
	}
	signer := &Signer{
		config: config,
		clock:  &fixedClock{time.Unix(123456789, 0)},
		noncer: &fixedNoncer{expectedNonce},
	}
	tr := &Transport{
		source: &ReuseTokenSource{NewToken(expectedToken, "some_secret"), nil},
		signer: signer,
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", server.URL, nil)
	assert.Nil(t, err)
	_, err = client.Do(req)
	assert.Nil(t, err)
}

func TestTransport_nilSource(t *testing.T) {
	tr := &Transport{
		source: nil,
		signer: &Signer{
			config: &Config{},
			clock:  &fixedClock{time.Unix(123456789, 0)},
			noncer: &fixedNoncer{"any_nonce"},
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://example.com")
	assert.Nil(t, resp)
	assert.Equal(t, "Get http://example.com: oauth1: Transport's source is nil", err.Error())
}

func TestTransport_nilSigner(t *testing.T) {
	tr := &Transport{
		source: &ReuseTokenSource{&Token{}, nil},
		signer: nil,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://example.com")
	assert.Nil(t, resp)
	assert.Equal(t, "Get http://example.com: oauth1: Transport's signer is nil", err.Error())
}

func newMockServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}
