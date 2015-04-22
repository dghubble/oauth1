package oauth1

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
)

const (
	oauthTokenSecretParam       = "oauth_token_secret"
	oauthCallbackConfirmedParam = "oauth_callback_confirmed"
)

// Config represents an OAuth1 consumer's (client's) credentials, callback URL,
// and the provider to which the consumer corresponds.
type Config struct {
	// Consumer Key (Client Identifier)
	ConsumerKey string
	// Consumer Secret (Client Shared-Secret)
	ConsumerSecret string
	// Callback URL
	CallbackURL string
	// Provider Endpoint specifying OAuth1 endpoint URLs
	Endpoint Endpoint
}

// NewConfig returns a new Config with the given consumer key and secret.
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

// NewClient returns a new http Client which signs requests via OAuth1.
func NewClient(config *Config, token *Token) *http.Client {
	transport := &Transport{
		source: &ReuseTokenSource{token, nil},
		signer: &Signer{config},
	}
	return &http.Client{Transport: transport}
}

// RequestToken represents OAuth1 temporary credentials as defined in RFC 5849
// 1.1 Terminology.
type RequestToken struct {
	Token       string
	TokenSecret string
}

// GetRequestToken obtains a RequestToken (temporary credential) by POSTing a
// signed request (with oauth_callback in the auth header) to the Endpoint
// RequestTokenURL. The request is signed by the consumer secret and an empty
// token secret. The response body form is validated to ensure
// oauth_callback_confirmed is true. Returns a new RequestToken with the
// oauth_token and oauth_token_secret in the body.
// See RFC 5849 2.1 Temporary Credentials.
func (c *Config) GetRequestToken() (*RequestToken, error) {
	req, err := http.NewRequest("POST", c.Endpoint.RequestTokenURL, nil)
	if err != nil {
		return nil, err
	}
	signer := &Signer{c}
	signer.SetRequestTokenAuthHeader(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// ParseQuery to decode URL-encoded application/x-www-form-urlencoded body
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	if values.Get(oauthCallbackConfirmedParam) != "true" {
		return nil, errors.New("oauth_callback_confirmed was not true")
	}
	token := values.Get(oauthTokenParam)
	tokenSecret := values.Get(oauthTokenSecretParam)
	if token == "" || tokenSecret == "" {
		return nil, errors.New("GetRequestToken response missing oauth token or secret")
	}
	return &RequestToken{Token: token, TokenSecret: tokenSecret}, nil
}

// AuthorizationURL accepts a consumer (client) RequestToken and returns a
// *url.URL the consumer should (re)direct the client (resource owner) to
// in order to authorize the consumer to act on his/her/its behalf. The url
// includes the required RequestToken.Token oauth_token as a query parameter.
// See RFC 5849 2.2 Resource Owner Authorization.
func (c *Config) AuthorizationURL(rt *RequestToken) (*url.URL, error) {
	authorizationURL, err := url.Parse(c.Endpoint.AuthorizeURL)
	if err != nil {
		return nil, err
	}
	values := authorizationURL.Query()
	values.Add(oauthTokenParam, rt.Token)
	authorizationURL.RawQuery = values.Encode()
	return authorizationURL, nil
}

// HandleAuthorizationCallback handles an OAuth1 authorization callback GET
// http.Request from a provider server. Request query parameters oauth_token
// and oauth_verifier are parsed and returned. The oauth_token (temporary
// credential) identifies the RequestToken pair obtained from GetRequestToken
// previously.
// See RFC 2.2 Resource Owner Authorization.
func (c *Config) HandleAuthorizationCallback(req *http.Request) (tokenKey, verifier string, err error) {
	// parse the raw query from the URL into req.Form
	err = req.ParseForm()
	if err != nil {
		return "", "", err
	}
	tokenKey = req.Form.Get(oauthTokenParam)
	verifier = req.Form.Get(oauthVerifierParam)
	if tokenKey == "" || verifier == "" {
		return "", "", errors.New("callback did not receive an oauth_token or oauth_verifier")
	}
	return tokenKey, verifier, nil
}

// GetAccessToken obtains an AccessToken (token credential) by POSTing a signed
// request (with oauth_token and oauth_verifier in the auth header) to the
// Endpoint AccessTokenURL. The request is signed by the consumer secret and
// request token secret pair. The access oauth_token and oauth_secret are
// read from the response body form to return an AccessToken.
// See RFC 2.3 Token Credentials.
func (c *Config) GetAccessToken(requestToken *RequestToken, verifier string) (*Token, error) {
	req, err := http.NewRequest("POST", c.Endpoint.AccessTokenURL, nil)
	if err != nil {
		return nil, err
	}
	signer := &Signer{c}
	signer.SetAccessTokenAuthHeader(req, requestToken, verifier)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	// when err is nil, resp contains a non-nil resp.Body which must be closed
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// ParseQuery to decode URL-encoded application/x-www-form-urlencoded body
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	token := values.Get(oauthTokenParam)
	tokenSecret := values.Get(oauthTokenSecretParam)
	if token == "" || tokenSecret == "" {
		return nil, errors.New("GetAccessToken response missing oauth token or secret")
	}
	return &Token{Token: token, TokenSecret: tokenSecret}, nil
}
