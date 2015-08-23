package oauth1

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
		//"dup": "fix",         // duplicate keys not supported
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

func TestCollectParameters(t *testing.T) {
	// example from RFC 5849 3.4.1.3.1
	oauthParams := map[string]string{
		"oauth_token":            "kkk9d7dh3k39sjv7",
		"oauth_consumer_key":     "9djdj82h48djs9d2",
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_timestamp":        "137131201",
		"oauth_nonce":            "7d8f3e4a",
	}
	values := url.Values{}
	values.Add("c2", "")
	values.Add("plus", "2 q") // duplicate keys not supported, a3 -> plus
	req, err := http.NewRequest("POST", "/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", strings.NewReader(values.Encode()))
	assert.Nil(t, err)
	req.Header.Set(contentType, formContentType)
	params, err := collectParameters(req, oauthParams)
	// assert parameters were collected from oauthParams, the query, and form body
	expected := map[string]string{
		"b5":                     "=%3D",
		"a3":                     "a",
		"c@":                     "",
		"a2":                     "r b",
		"oauth_token":            "kkk9d7dh3k39sjv7",
		"oauth_consumer_key":     "9djdj82h48djs9d2",
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_timestamp":        "137131201",
		"oauth_nonce":            "7d8f3e4a",
		"c2":                     "",
		"plus":                   "2 q",
	}
	assert.Nil(t, err)
	assert.Equal(t, expected, params)
	// RFC 5849 3.4.1.3.1 requires a {"a3"="2 q"} be form encoded to "a3=2+q" in
	// the application/x-www-form-urlencoded body. The parameter "2+q" should be
	// read as "2 q" and percent encoded to "2%20q".
	// In Go, data is form encoded by calling Encode on url.Values{} (URL
	// encoding) and decoded with url.ParseQuery to url.Values. So the encoding
	// of "2 q" to "2+q" and decoding back to "2 q" is handled and then params
	// are percent encoded.
	// http://golang.org/src/net/http/client.go#L496
	// http://golang.org/src/net/http/request.go#L837
}

func TestNormalizedParameterString(t *testing.T) {
	simple := map[string]string{
		"a": "b & c",
		"☃": "snowman",
	}
	rfcExample := map[string]string{
		"b5":                     "=%3D",
		"a3":                     "a",
		"c@":                     "",
		"a2":                     "r b",
		"oauth_token":            "kkk9d7dh3k39sjv7",
		"oauth_consumer_key":     "9djdj82h48djs9d2",
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_timestamp":        "137131201",
		"oauth_nonce":            "7d8f3e4a",
		"c2":                     "",
		"plus":                   "2 q",
	}
	cases := []struct {
		params     map[string]string
		authHeader string
	}{
		{simple, "%E2%98%83=snowman&a=b%20%26%20c"},
		{rfcExample, "a2=r%20b&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7&plus=2%20q"},
	}
	for _, c := range cases {
		assert.Equal(t, c.authHeader, normalizedParameterString(c.params))
	}
}
