package oauth1

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	AUTHORIZATION_HEADER     = "Authorization"
	AUTHORIZATION_PREFIX     = "OAuth " // trailing space is intentional
	OAUTH_CONSUMER_KEY       = "oauth_consumer_key"
	OAUTH_NONCE              = "oauth_nonce"
	OAUTH_SIGNATURE          = "oauth_signature"
	OAUTH_SIGNATURE_METHOD   = "oauth_signature_method"
	OAUTH_TIMESTAMP          = "oauth_timestamp"
	OAUTH_TOKEN              = "oauth_token"
	OAUTH_VERSION            = "oauth_version"
	DEFAULT_SIGNATURE_METHOD = "HMAC-SHA1"
	DEFAULT_VERSION          = "1.0"
)

// Handles signing requests and setting authorization header
type Signer struct {
	config *Config
}

// Sign sets an authorization header on the request with the oauth
// parameters including the oauth_signature digest.
func (s *Signer) Sign(req *http.Request, token *Token) {
	oauthParams := s.oauthParams(req, token)
	req.Header.Set(AUTHORIZATION_HEADER, authorizationHeader(oauthParams))
}

// oauthParams returns a map of the OAuth1 protocol parameters including the
// "oauth_signature" parameter with signature value.
func (s *Signer) oauthParams(req *http.Request, token *Token) map[string]string {
	oauthParams := basicOAuthParams(s.config.ConsumerKey, token.Token)
	signatureBase := signatureBase(req, oauthParams)
	signature := signature(s.config.ConsumerSecret, token.TokenSecret, signatureBase)
	oauthParams[OAUTH_SIGNATURE] = signature
	return oauthParams
}

// authorizationHeader combines the OAuth1 protocol parameters into an
// Authorization header according to RFC5849 3.5.1.
// The oauthParams should include the "oauth_signature" key/value pair.
// Does not mutate the oauthParams.
func authorizationHeader(oauthParams map[string]string) string {
	// percent encode
	params := map[string]string{}
	for key, value := range oauthParams {
		params[PercentEncode(key)] = PercentEncode(value)
	}
	// parameter join
	pairs := make([]string, len(params))
	i := 0
	for key, value := range params {
		pairs[i] = fmt.Sprintf("%s=%s", key, value)
		i++
	}
	return AUTHORIZATION_PREFIX + strings.Join(pairs, ", ")
}

// basicOAuthParams returns a map of the OAuth1 protocol parameters excluding
// the "oauth_signature" parameter.
func basicOAuthParams(consumerKey, token string) map[string]string {
	return map[string]string{
		OAUTH_CONSUMER_KEY:     consumerKey,
		OAUTH_NONCE:            nonce(),
		OAUTH_SIGNATURE_METHOD: DEFAULT_SIGNATURE_METHOD,
		OAUTH_TIMESTAMP:        strconv.FormatInt(epoch(), 10),
		OAUTH_TOKEN:            token,
		OAUTH_VERSION:          DEFAULT_VERSION,
	}
}

// signatureBase combines the uppercase request method, percent encoded base
// string URI, and parameter string. Returns the OAuth1 signature base string
// according to RFC5849 3.4.1.
// Does not mutate the Request or basicOAuthParams.
func signatureBase(req *http.Request, basicOAuthParams map[string]string) string {
	method := strings.ToUpper(req.Method)
	baseUrl := strings.Split(req.URL.String(), "?")[0]
	// add oauth, query, and body parameters into params
	params := map[string]string{}
	for key, value := range req.URL.Query() {
		// most backends do not accept duplicate query keys
		params[key] = value[0]
	}
	// TODO: support Body params
	for key, value := range basicOAuthParams {
		params[key] = value
	}
	// encode params into a parameter string (RFC5849 3.4.1.3, 3.4.1.3.2)
	parameterString := encodeParams(params)
	baseParts := []string{method, PercentEncode(baseUrl), PercentEncode(parameterString)}
	return strings.Join(baseParts, "&")
}

// encodeParams percent encodes parameter keys and values (RFC5849 3.6 and
// RFC3986 2.1), sorts parameters by key, and formats them into a parameter
// string (RFC5894 3.4.1.3.2, e.g. foo=bar&q=gopher).
func encodeParams(unencodedParams map[string]string) string {
	// percent encode
	params := map[string]string{}
	for key, value := range unencodedParams {
		params[PercentEncode(key)] = PercentEncode(value)
	}
	// sort by key
	keys := make([]string, len(params))
	i := 0
	for key, _ := range params {
		keys[i] = key
		i++
	}
	sort.Strings(keys)
	// parameter join
	pairs := make([]string, len(params))
	for i, key := range keys {
		pairs[i] = fmt.Sprintf("%s=%s", key, params[key])
	}
	return strings.Join(pairs, "&")
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

// Returns a base64 encoded random 32 bytes.
func nonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Returns the epoch
func epoch() int64 {
	return time.Now().Unix()
}
