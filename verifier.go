package oauth1

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	XForwardedProto = "X-Forwarded-Proto"
	ForwardedHeader = "Forwarded"

	ForwardedHeaderProtoField = "proto"
)

// Verifier verifies a OAuth1 signature based on base string.
type Verifier interface {
	Verify(baseString, actualSignature string) error
}

// GetVerifier returns a verifier based on consumer key & signature method.
//
// GetVerifier should also make sure nonce is unique across all requests with the
// same timestamp, client credentials, and token combinations.
type GetVerifier func(consumerKey, signatureMethod string, params map[string]string) (Verifier, error)

// VerifierManager verifies OAuth1 request.
// VerifierManager does NOT support duplicated parameters.
type VerifierManager struct {
	// verifier should find the corresponding verifier according to the consumer key & signature method.
	verifier GetVerifier
	// defaultScheme implies the scheme that should be used in verification
	// if scheme cannot be found from request.
	defaultScheme string
	// maxClockSkew limits the max timestamp difference between client and server.
	// Negative value implies no limit.
	maxClockSkew time.Duration
}

// NewVerifierManager initializes VerifierManager.
// For the meaning of each field, please refer to the VerifierManager.
func NewVerifierManager(getVerifier GetVerifier, defaultScheme string, maxClockSkew time.Duration) *VerifierManager {
	return &VerifierManager{
		verifier:      getVerifier,
		defaultScheme: defaultScheme,
		maxClockSkew:  maxClockSkew,
	}
}

// Verify verifies a OAuth1 request.
// NOT supporting duplicated parameters.
// NOT examining whether nonce is unique across all requests with the
// same timestamp, client credentials, and token combinations.
func (v *VerifierManager) Verify(req *http.Request) error {
	v.makeURLAbs(req)
	params, actualSignature, err := collectRequestParameters(req)
	if err != nil {
		return fmt.Errorf("oauth1: error collecting request parameters: %w", err)
	}

	timestamp := params[oauthTimestampParam]
	err = v.checkTimestamp(timestamp)
	if err != nil {
		return fmt.Errorf("oauth1: error checking timestamp: %w", err)
	}

	consumerKey := params[oauthConsumerKeyParam]
	signatureMethod := params[oauthSignatureMethodParam]
	verifier, err := v.verifier(consumerKey, signatureMethod, params)
	if err != nil {
		return fmt.Errorf("oauth1: error getting verifier: %w", err)
	}

	baseString := signatureBase(req, params)
	err = verifier.Verify(baseString, actualSignature)
	if err != nil {
		return fmt.Errorf("oauth1: error verifying signature: %w", err)
	}
	return nil
}

// checkTimestamp only supports timestamp that is expressed in the number of seconds since January 1, 1970 00:00:00 GMT.
// https://datatracker.ietf.org/doc/html/rfc5849#section-3.3
// Unless otherwise specified by the server's documentation,
// the timestamp is expressed in the number of seconds since January 1, 1970 00:00:00 GMT.
func (v *VerifierManager) checkTimestamp(rawTimestamp string) error {
	if v.maxClockSkew < 0 {
		return nil
	}

	timestamp, err := strconv.ParseInt(rawTimestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("oauth1: error parsing timestamp: %w", err)
	}
	t := time.Unix(timestamp, 0)
	now := time.Now()
	if now.Sub(t) > v.maxClockSkew {
		return fmt.Errorf(
			"oauth1: clock skew out of sync. timestamp in request: %v, server timestamp: %v",
			timestamp, now.Unix(),
		)
	}
	return nil
}

// RSAVerifier verifies OAuth1 signatures.
type RSAVerifier struct {
	publicKey *rsa.PublicKey
	hash      crypto.Hash
}

// NewRSAVerifier initializes RSAVerifier with rsa public key & hash.
func NewRSAVerifier(publicKey *rsa.PublicKey, hash crypto.Hash) *RSAVerifier {
	return &RSAVerifier{
		publicKey,
		hash,
	}
}

// Verify verifies the signature based on base string using rsa + hash selected in initialization.
func (v *RSAVerifier) Verify(baseString, actualSignature string) error {
	// https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.3
	// signature is base64 encoded
	signature, err := base64.StdEncoding.DecodeString(actualSignature)
	if err != nil {
		return fmt.Errorf("oauth1: error base64 decoding signature: %w", err)
	}

	hash := v.hash.New()
	_, err = hash.Write([]byte(baseString))
	if err != nil {
		return fmt.Errorf("oauth1: error hashing parameters: %w", err)
	}
	digest := hash.Sum(nil)

	err = rsa.VerifyPKCS1v15(v.publicKey, v.hash, digest[:], signature)
	if err != nil {
		return fmt.Errorf("oauth1: error verifying rsa signature: %w", err)
	}
	return nil
}

// HMACVerifier verifies OAuth1 signatures.
type HMACVerifier struct {
	signer      Signer
	tokenSecret string
}

// NewHMACVerifier initializes HMACVerifier with hmac signer &
// optional oauth token secret.
// Default signer is HMAC-SHA1.
func NewHMACVerifier(c *Config, tokenSecret string) *HMACVerifier {
	return &HMACVerifier{
		newAuther(c).signer(),
		tokenSecret,
	}
}

// Verify verifies the signature based on base string using hmac + hash selected in initialization.
func (v *HMACVerifier) Verify(baseString, actualSignature string) error {
	// https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.2
	// signature is base64 encoded
	// Be careful, Signer.Sign() returns base64-encoded signature
	expectedSignature, err := v.signer.Sign(v.tokenSecret, baseString)
	if err != nil {
		return fmt.Errorf("oauth1: error signing request for validating signature: %w", err)
	}

	// https://datatracker.ietf.org/doc/html/rfc5849#section-3.5.1
	// Still there are clients that don't escape signature
	if actualSignature != expectedSignature {
		return fmt.Errorf("oauth1: invalid signature")
	}
	return nil
}

// collectRequestParameters collects request parameters from
//   1. the request query,
//   2. the request body provided the body is single part & form encoded & form content type header is set,
//   3. and authorization header.
// The returned map of collected parameter keys and values follow RFC 5849 3.4.1.3,
// except duplicate parameters are not supported.
func collectRequestParameters(req *http.Request) (map[string]string, string, error) {
	// parse from query string & body
	params, err := collectParameters(req, nil)
	if err != nil {
		return nil, "", err
	}

	// https://datatracker.ietf.org/doc/html/rfc5849#section-3.5.1
	// according to 3.5.1.
	// protocol parameters can be transmitted using the HTTP "Authorization" header field
	// with the auth-scheme name set to "OAuth" (case insensitive).
	authHeader := req.Header.Get(authorizationHeaderParam)
	if strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(authorizationPrefix)) {
		// case-insensitively trim prefix
		authHeader = authHeader[len(authorizationPrefix):]

		// https://datatracker.ietf.org/doc/html/rfc5849#section-3.5.1
		// according to 3.5.1. parameters are separated by a "," character (ASCII code 44) and OPTIONAL linear whitespace per
		for _, raw := range strings.Split(authHeader, ",") {
			raw = strings.TrimSpace(raw)
			// https://datatracker.ietf.org/doc/html/rfc5849#section-3.5.1
			// according to 3.5.1. key & value are separated by =
			kv := strings.SplitN(raw, "=", 2)

			k := kv[0]
			// https://datatracker.ietf.org/doc/html/rfc5849#section-3.5.1
			// according to 3.5.1. unescape key
			k, err := PercentDecode(k)
			if err != nil {
				return nil, "", fmt.Errorf("oauth1: error unescaping authorization field name: %w", err)
			}
			// https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.1.3.1
			// according to 3.4.1.3.1. the realm parameter is excluded
			if k == realmParam {
				continue
			}

			// https://datatracker.ietf.org/doc/html/rfc5849#section-3.5.1
			// according to 3.5.1. value is wrapped by "
			v := strings.Trim(kv[1], `"`)
			// https://datatracker.ietf.org/doc/html/rfc5849#section-3.5.1
			// according to 3.5.1. unescape value
			v, err = PercentDecode(v)
			if err != nil {
				return nil, "", fmt.Errorf("oauth1: error unescaping oauth parameters")
			}
			// dghubble does NOT support params with duplicate keys
			params[k] = v
		}
	}

	signatureBase64 := params[oauthSignatureParam]
	delete(params, oauthSignatureParam)

	return params, signatureBase64, nil
}

// makeURLAbs tries to make sure request url has scheme & host.
// If missing host, makeURLAbs gets it from request.Host.
// If missing scheme, makeURLAbs tries to get it from header.
// Currently makeURLAbs only utilizes in Forwarded & X-Forwarded-Proto.
func (v *VerifierManager) makeURLAbs(req *http.Request) {
	if req.URL.IsAbs() {
		return
	}
	// we need scheme & host
	req.URL.Host = req.Host

	raw := req.Header.Get(ForwardedHeader) // standard
	scheme := parseForwardedHeader(raw)[ForwardedHeaderProtoField]
	if len(scheme) != 0 {
		req.URL.Scheme = scheme
		return
	}
	scheme = req.Header.Get(XForwardedProto) // de-facto standard
	if len(scheme) != 0 {
		req.URL.Scheme = scheme
		return
	}
	req.URL.Scheme = v.defaultScheme
}

// parseForwardedHeader parses Forwarded header.
// parseForwardedHeader does NOT return nil.
//
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
// from Google: for="127.0.0.1";proto=https
func parseForwardedHeader(forwarded string) map[string]string {
	result := map[string]string{}
	if len(forwarded) == 0 {
		return result
	}
	for _, pair := range strings.Split(forwarded, ";") {
		kv := strings.SplitN(pair, "=", 2)
		result[kv[0]] = kv[1]
	}
	return result
}
