package oauth1

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	authorizationHeaderParam  = "Authorization"
	authorizationPrefix       = "OAuth " // trailing space is intentional
	oauthConsumerKeyParam     = "oauth_consumer_key"
	oauthNonceParam           = "oauth_nonce"
	oauthSignatureParam       = "oauth_signature"
	oauthSignatureMethodParam = "oauth_signature_method"
	oauthTimestampParam       = "oauth_timestamp"
	oauthTokenParam           = "oauth_token"
	oauthVersionParam         = "oauth_version"
	oauthCallbackParam        = "oauth_callback"
	oauthVerifierParam        = "oauth_verifier"
	defaultSignatureMethod    = "HMAC-SHA1"
	defaultOauthVersion       = "1.0"
	contentType               = "Content-Type"
	formContentType           = "application/x-www-form-urlencoded"
)

// Signer handles signing requests and setting the authorization header.
type Signer struct {
	config *Config
	clock  clock
	noncer noncer
}

// SetRequestTokenAuthHeader adds the OAuth1 header for the request token
// request (temporary credential) according to RFC 5849 2.1.
func (s *Signer) SetRequestTokenAuthHeader(req *http.Request) error {
	oauthParams := s.commonOAuthParams()
	oauthParams[oauthCallbackParam] = s.config.CallbackURL
	signatureBase, err := signatureBase(req, oauthParams)
	if err != nil {
		return err
	}
	signature := signature(s.config.ConsumerSecret, "", signatureBase)
	oauthParams[oauthSignatureParam] = signature
	setAuthorizationHeader(req, oauthParams)
	return nil
}

// SetAccessTokenAuthHeader sets the OAuth1 header for the access token request
// (token credential) according to RFC 5849 2.3.
func (s *Signer) SetAccessTokenAuthHeader(req *http.Request, requestToken *RequestToken, verifier string) error {
	oauthParams := s.commonOAuthParams()
	oauthParams[oauthTokenParam] = requestToken.Token
	oauthParams[oauthVerifierParam] = verifier
	signatureBase, err := signatureBase(req, oauthParams)
	if err != nil {
		return err
	}
	signature := signature(s.config.ConsumerSecret, requestToken.TokenSecret, signatureBase)
	oauthParams[oauthSignatureParam] = signature
	setAuthorizationHeader(req, oauthParams)
	return nil
}

// SetRequestAuthHeader sets the OAuth1 header for making authenticated
// requests with an AccessToken (token credential) according to RFC 5849 3.1.
func (s *Signer) SetRequestAuthHeader(req *http.Request, accessToken *Token) error {
	oauthParams := s.commonOAuthParams()
	oauthParams[oauthTokenParam] = accessToken.Token
	signatureBase, err := signatureBase(req, oauthParams)
	if err != nil {
		return err
	}
	signature := signature(s.config.ConsumerSecret, accessToken.TokenSecret, signatureBase)
	oauthParams[oauthSignatureParam] = signature
	setAuthorizationHeader(req, oauthParams)
	return nil
}

// commonOAuthParams returns a map of the common OAuth1 protocol parameters,
// excluding the oauth_signature parameter.
func (s *Signer) commonOAuthParams() map[string]string {
	return map[string]string{
		oauthConsumerKeyParam:     s.config.ConsumerKey,
		oauthSignatureMethodParam: defaultSignatureMethod,
		oauthTimestampParam:       strconv.FormatInt(s.epoch(), 10),
		oauthNonceParam:           s.nonce(),
		oauthVersionParam:         defaultOauthVersion,
	}
}

// Returns a base64 encoded random 32 bytes.
func (s *Signer) nonce() string {
	if s.noncer != nil {
		return s.noncer.Nonce()
	}
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Returns the Unix epoch seconds.
func (s *Signer) epoch() int64 {
	return s.clock.Now().Unix()
}

// setAuthorizationHeader formats the OAuth1 protocol parameters into a header
// and sets the header on the Request.
func setAuthorizationHeader(req *http.Request, oauthParams map[string]string) {
	authHeader := authHeaderValue(oauthParams)
	req.Header.Set(authorizationHeaderParam, authHeader)
}

// authHeaderValue formats OAuth parameters according to RFC 5849 3.5.1. OAuth
// params are percent encoded, sorted by key (for testability), and joined by
// "=" into pairs. Pairs are joined with a ", " comma separator into a header
// string.
// The given OAuth params should include the "oauth_signature" key.
func authHeaderValue(oauthParams map[string]string) string {
	pairs := sortParameters(encodeParameters(oauthParams))
	return authorizationPrefix + strings.Join(pairs, ", ")
}

// signatureBase combines the uppercase request method, percent encoded base
// string URI, and parameter string. Returns the OAuth1 signature base string
// according to RFC5849 3.4.1.
// Does not mutate the Request or oauthParams.
func signatureBase(req *http.Request, oauthParams map[string]string) (string, error) {
	method := strings.ToUpper(req.Method)
	baseURL := strings.Split(req.URL.String(), "?")[0]
	// add oauth, query, and body parameters into params
	params := map[string]string{}
	for key, value := range req.URL.Query() {
		// most backends do not accept duplicate query keys
		params[key] = value[0]
	}
	if req.Body != nil && req.Header.Get(contentType) == formContentType {
		// reads data to a []byte, draining req.Body
		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return "", err
		}
		values, err := url.ParseQuery(string(b))
		if err != nil {
			return "", err
		}
		for key, value := range values {
			params[key] = value[0]
		}
		// reinitialize Body with ReadCloser over the []byte
		req.Body = ioutil.NopCloser(bytes.NewReader(b))
	}
	for key, value := range oauthParams {
		params[key] = value
	}
	// params are encoded, sorted by key, and joined with = and & (e.g. foo=bar&q=gopher)
	// to produce a parameter string according to RFC5894 3.4.1.3.2
	parameterString := strings.Join(sortParameters(encodeParameters(params)), "&")
	// signature base string constructed accoding to 3.4.1.1
	baseParts := []string{method, PercentEncode(baseURL), PercentEncode(parameterString)}
	return strings.Join(baseParts, "&"), nil
}

// encodeParameters percent encodes parameter keys and values according to
// RFC5849 3.6 and RFC3986 2.1 and returns a new map.
func encodeParameters(params map[string]string) map[string]string {
	encoded := map[string]string{}
	for key, value := range params {
		encoded[PercentEncode(key)] = PercentEncode(value)
	}
	return encoded
}

// sortParameters sorts parameters by key and returns a slice of key=value
// pair strings.
func sortParameters(params map[string]string) []string {
	// sort by key
	keys := make([]string, len(params))
	i := 0
	for key := range params {
		keys[i] = key
		i++
	}
	sort.Strings(keys)
	// parameter join
	pairs := make([]string, len(params))
	for i, key := range keys {
		pairs[i] = fmt.Sprintf("%s=%s", key, params[key])
	}
	return pairs
}

// signature creates a signing key from the consumer and token secrets and
// calculates the HMAC signature bytes of the message using the SHA1 hash.
// Returns the base64 encoded signature.
func signature(consumerSecret, tokenSecret, message string) string {
	signingKey := strings.Join([]string{consumerSecret, tokenSecret}, "&")
	mac := hmac.New(sha1.New, []byte(signingKey))
	mac.Write([]byte(message))
	signatureBytes := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(signatureBytes)
}
