package oauth1

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	expectedVersion         = "1.0"
	expectedSignatureMethod = "HMAC-SHA1"
)

func TestSetRequestTokenAuthHeader(t *testing.T) {
	// example from https://dev.twitter.com/web/sign-in/implementing
	var unixTimestamp int64 = 1318467427
	expectedConsumerKey := "cChZNFj6T5R0TigYB9yd1w"
	expectedCallback := "http%3A%2F%2Flocalhost%2Fsign-in-with-twitter%2F"
	expectedSignature := "F1Li3tvehgcraF8DMJ7OyxO4w9Y%3D"
	expectedTimestamp := "1318467427"
	expectedNonce := "ea9ec8429b68d6b77cd5600adbbb0456"
	config := &Config{
		ConsumerKey:    expectedConsumerKey,
		ConsumerSecret: "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg",
		CallbackURL:    "http://localhost/sign-in-with-twitter/",
		Endpoint: Endpoint{
			RequestTokenURL: "https://api.twitter.com/oauth/request_token",
			AuthorizeURL:    "https://api.twitter.com/oauth/authorize",
			AccessTokenURL:  "https://api.twitter.com/oauth/access_token",
		},
	}

	signer := &Signer{config, &fixedClock{time.Unix(unixTimestamp, 0)}, &fixedNoncer{expectedNonce}}
	req, err := http.NewRequest("POST", config.Endpoint.RequestTokenURL, nil)
	err = signer.SetRequestTokenAuthHeader(req)
	// assert the request for a request token is signed and has an oauth_callback
	assert.Nil(t, err)
	params := parseOAuthParamsOrFail(t, req.Header.Get(authorizationHeaderParam))
	assert.Equal(t, expectedCallback, params[oauthCallbackParam])
	assert.Equal(t, expectedSignature, params[oauthSignatureParam])
	// additional OAuth parameters
	assert.Equal(t, expectedConsumerKey, params[oauthConsumerKeyParam])
	assert.Equal(t, expectedNonce, params[oauthNonceParam])
	assert.Equal(t, expectedTimestamp, params[oauthTimestampParam])
	assert.Equal(t, expectedVersion, params[oauthVersionParam])
	assert.Equal(t, expectedSignatureMethod, params[oauthSignatureMethodParam])
}

func TestSetAccessTokenAuthHeader(t *testing.T) {
	// example from https://dev.twitter.com/web/sign-in/implementing
	var unixTimestamp int64 = 1318467427
	expectedConsumerKey := "cChZNFj6T5R0TigYB9yd1w"
	expectedRequestToken := "NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0"
	requestTokenSecret := "veNRnAWe6inFuo8o2u8SLLZLjolYDmDP7SzL0YfYI"
	expectedVerifier := "uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY"
	expectedSignature := "39cipBtIOHEEnybAR4sATQTpl2I%3D"
	expectedTimestamp := "1318467427"
	expectedNonce := "a9900fe68e2573b27a37f10fbad6a755"
	config := &Config{
		ConsumerKey:    expectedConsumerKey,
		ConsumerSecret: "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg",
		Endpoint: Endpoint{
			RequestTokenURL: "https://api.twitter.com/oauth/request_token",
			AuthorizeURL:    "https://api.twitter.com/oauth/authorize",
			AccessTokenURL:  "https://api.twitter.com/oauth/access_token",
		},
	}

	signer := &Signer{config, &fixedClock{time.Unix(unixTimestamp, 0)}, &fixedNoncer{expectedNonce}}
	req, err := http.NewRequest("POST", config.Endpoint.AccessTokenURL, nil)
	requestToken := &RequestToken{expectedRequestToken, requestTokenSecret}
	err = signer.SetAccessTokenAuthHeader(req, requestToken, expectedVerifier)
	// assert the request for an access token is signed and has an oauth_token and verifier
	assert.Nil(t, err)
	params := parseOAuthParamsOrFail(t, req.Header.Get(authorizationHeaderParam))
	assert.Equal(t, expectedRequestToken, params[oauthTokenParam])
	assert.Equal(t, expectedVerifier, params[oauthVerifierParam])
	assert.Equal(t, expectedSignature, params[oauthSignatureParam])
	// additional OAuth parameters
	assert.Equal(t, expectedConsumerKey, params[oauthConsumerKeyParam])
	assert.Equal(t, expectedNonce, params[oauthNonceParam])
	assert.Equal(t, expectedTimestamp, params[oauthTimestampParam])
	assert.Equal(t, expectedVersion, params[oauthVersionParam])
	assert.Equal(t, expectedSignatureMethod, params[oauthSignatureMethodParam])
}

func TestEncodeParameters(t *testing.T) {
	input := map[string]string{
		"a": "Dogs, Cats & Mice",
		"☃": "snowman",
		"ル": "ル",
	}
	expected := map[string]string{
		"a":         "Dogs%2C%20Cats%20%26%20Mice",
		"%E2%98%83": "snowman",
		"%E3%83%AB": "%E3%83%AB",
	}
	assert.Equal(t, expected, encodeParameters(input))
}

func TestSortParameters(t *testing.T) {
	input := map[string]string{
		".":         "ape",
		"5.6":       "bat",
		"rsa":       "cat",
		"%20":       "dog",
		"%E3%83%AB": "eel",
		"dup":       "fox",
		//"dup": "fix", // sort by value if keys match
	}
	expected := []string{
		"%20=dog",
		"%E3%83%AB=eel",
		".=ape",
		"5.6=bat",
		"dup=fox",
		"rsa=cat",
	}
	assert.Equal(t, expected, sortParameters(input))
}

func TestCommonOAuthParams(t *testing.T) {
	config := &Config{ConsumerKey: "some_consumer_key"}
	signer := &Signer{config, &fixedClock{time.Unix(50037133, 0)}, &fixedNoncer{"some_nonce"}}
	expectedParams := map[string]string{
		"oauth_consumer_key":     "some_consumer_key",
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_timestamp":        "50037133",
		"oauth_nonce":            "some_nonce",
		"oauth_version":          "1.0",
	}
	assert.Equal(t, expectedParams, signer.commonOAuthParams())
}

func TestAuthHeaderValue(t *testing.T) {
	cases := []struct {
		params     map[string]string
		authHeader string
	}{
		{map[string]string{}, "OAuth "},
		{map[string]string{"a": "b"}, "OAuth a=b"},
		{map[string]string{"a": "b", "c": "d", "e": "f", "1": "2"}, "OAuth 1=2, a=b, c=d, e=f"},
		{map[string]string{"/= +doencode": "/= +doencode"}, "OAuth %2F%3D%20%2Bdoencode=%2F%3D%20%2Bdoencode"},
		{map[string]string{"-._~dontencode": "-._~dontencode"}, "OAuth -._~dontencode=-._~dontencode"},
	}
	for _, c := range cases {
		assert.Equal(t, c.authHeader, authHeaderValue(c.params))
	}
}

func parseOAuthParamsOrFail(t *testing.T, authHeader string) map[string]string {
	if !strings.HasPrefix(authHeader, authorizationPrefix) {
		assert.Fail(t, fmt.Sprintf("Expected Authorization header to start with \"%s\", got \"%s\"", authorizationPrefix, authHeader[:len(authorizationPrefix)+1]))
	}
	params := map[string]string{}
	for _, pairStr := range strings.Split(authHeader[len(authorizationPrefix):], ", ") {
		pair := strings.Split(pairStr, "=")
		if len(pair) != 2 {
			assert.Fail(t, "Error parsing OAuth parameter %s", pairStr)
		}
		params[pair[0]] = pair[1]
	}
	return params
}

type fixedClock struct {
	now time.Time
}

func (c *fixedClock) Now() time.Time {
	return c.now
}

type fixedNoncer struct {
	nonce string
}

func (n *fixedNoncer) Nonce() string {
	return n.nonce
}
