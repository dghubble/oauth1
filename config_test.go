package oauth1

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

const expectedVerifier = "some_verifier"

func TestNewConfig(t *testing.T) {
	expectedConsumerKey := "consumer_key"
	expectedConsumerSecret := "consumer_secret"
	config := NewConfig(expectedConsumerKey, expectedConsumerSecret)
	assert.Equal(t, expectedConsumerKey, config.ConsumerKey)
	assert.Equal(t, expectedConsumerSecret, config.ConsumerSecret)
}

func TestNewClient(t *testing.T) {
	expectedToken := "access_token"
	expectedConsumerKey := "consumer_key"
	config := NewConfig(expectedConsumerKey, "consumer_secret")
	token := NewToken(expectedToken, "access_secret")
	client := config.Client(token)

	server := newMockServer(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "GET", req.Method)
		params := parseOAuthParamsOrFail(t, req.Header.Get(authorizationHeaderParam))
		assert.Equal(t, expectedToken, params[oauthTokenParam])
		assert.Equal(t, expectedConsumerKey, params[oauthConsumerKeyParam])
	})
	defer server.Close()
	client.Get(server.URL)
}

// newRequestTokenServer returns a new mock httptest.Server for an OAuth1
// provider request token endpoint.
func newRequestTokenServer(t *testing.T, data url.Values) *httptest.Server {
	return newMockServer(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "POST", req.Method)
		assert.NotEmpty(t, req.Header.Get("Authorization"))
		w.Header().Set(contentType, formContentType)
		w.Write([]byte(data.Encode()))
	})
}

// newAccessTokenServer returns a new mock httptest.Server for an OAuth1
// provider access token endpoint.
func newAccessTokenServer(t *testing.T, data url.Values) *httptest.Server {
	return newMockServer(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "POST", req.Method)
		assert.NotEmpty(t, req.Header.Get("Authorization"))
		params := parseOAuthParamsOrFail(t, req.Header.Get(authorizationHeaderParam))
		assert.Equal(t, expectedVerifier, params[oauthVerifierParam])
		w.Header().Set(contentType, formContentType)
		w.Write([]byte(data.Encode()))
	})
}

func TestConfigRequestToken(t *testing.T) {
	expectedToken := "token"
	expectedSecret := "secret"
	data := url.Values{}
	data.Add("oauth_token", expectedToken)
	data.Add("oauth_token_secret", expectedSecret)
	data.Add("oauth_callback_confirmed", "true")
	server := newRequestTokenServer(t, data)
	defer server.Close()

	config := &Config{
		Endpoint: Endpoint{
			RequestTokenURL: server.URL,
		},
	}
	requestToken, requestSecret, err := config.RequestToken()
	assert.Nil(t, err)
	assert.Equal(t, expectedToken, requestToken)
	assert.Equal(t, expectedSecret, requestSecret)
}

func TestConfigRequestToken_InvalidRequestTokenURL(t *testing.T) {
	config := &Config{
		Endpoint: Endpoint{
			RequestTokenURL: "http://wrong.com/oauth/request_token",
		},
	}
	requestToken, requestSecret, err := config.RequestToken()
	assert.NotNil(t, err)
	assert.Equal(t, "", requestToken)
	assert.Equal(t, "", requestSecret)
}

func TestConfigRequestToken_CallbackNotConfirmed(t *testing.T) {
	data := url.Values{}
	data.Add("oauth_callback_confirmed", "false")
	server := newRequestTokenServer(t, data)
	defer server.Close()

	config := &Config{
		Endpoint: Endpoint{
			RequestTokenURL: server.URL,
		},
	}
	requestToken, requestSecret, err := config.RequestToken()
	if assert.Error(t, err) {
		assert.Equal(t, "oauth_callback_confirmed was not true", err.Error())
	}
	assert.Equal(t, "", requestToken)
	assert.Equal(t, "", requestSecret)
}

func TestConfigRequestToken_MissingTokenOrSecret(t *testing.T) {
	data := url.Values{}
	data.Add("oauth_token", "any_token")
	data.Add("oauth_callback_confirmed", "true")
	server := newRequestTokenServer(t, data)
	defer server.Close()

	config := &Config{
		Endpoint: Endpoint{
			RequestTokenURL: server.URL,
		},
	}
	requestToken, requestSecret, err := config.RequestToken()
	if assert.Error(t, err) {
		assert.Equal(t, "Response missing oauth token or secret", err.Error())
	}
	assert.Equal(t, "", requestToken)
	assert.Equal(t, "", requestSecret)
}

func TestAuthorizationURL(t *testing.T) {
	expectedURL := "https://api.example.com/oauth/authorize?oauth_token=a%2Frequest_token"
	config := &Config{
		Endpoint: Endpoint{
			AuthorizeURL: "https://api.example.com/oauth/authorize",
		},
	}
	url, err := config.AuthorizationURL("a/request_token")
	assert.Nil(t, err)
	if assert.NotNil(t, url) {
		assert.Equal(t, expectedURL, url.String())
	}
}

func TestAuthorizationURL_CannotParseAuthorizeURL(t *testing.T) {
	config := &Config{
		Endpoint: Endpoint{
			AuthorizeURL: "http://[::1]invalid",
		},
	}
	url, err := config.AuthorizationURL("any_request_token")
	assert.Nil(t, url)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "parse")
		assert.Contains(t, err.Error(), "invalid port")
	}
}

func TestConfigAccessToken(t *testing.T) {
	expectedToken := "token"
	expectedSecret := "secret"
	data := url.Values{}
	data.Add("oauth_token", expectedToken)
	data.Add("oauth_token_secret", expectedSecret)
	data.Add("oauth_callback_confirmed", "true")
	server := newAccessTokenServer(t, data)
	defer server.Close()

	config := &Config{
		Endpoint: Endpoint{
			AccessTokenURL: server.URL,
		},
	}
	accessToken, accessSecret, err := config.AccessToken("request_token", "request_secret", expectedVerifier)
	assert.Nil(t, err)
	assert.Equal(t, expectedToken, accessToken)
	assert.Equal(t, expectedSecret, accessSecret)
}

func TestConfigAccessToken_MissingTokenOrSecret(t *testing.T) {
	data := url.Values{}
	data.Add("oauth_token", "any_token")
	server := newAccessTokenServer(t, data)
	defer server.Close()

	config := &Config{
		Endpoint: Endpoint{
			AccessTokenURL: server.URL,
		},
	}
	accessToken, accessSecret, err := config.AccessToken("request_token", "request_secret", expectedVerifier)
	if assert.Error(t, err) {
		assert.Equal(t, "Response missing oauth token or secret", err.Error())
	}
	assert.Equal(t, "", accessToken)
	assert.Equal(t, "", accessSecret)
}
