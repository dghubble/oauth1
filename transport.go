package oauth1

import (
	"fmt"
	"net/http"
)

// Transport is an http.RoundTripper which makes OAuth1 HTTP requests. It
// wraps a base RoundTripper and adds an Authorization header using an
// OAuth1 signer and TokenSource.
//
// Transport is a low-level component, most users should use Config to create
// an http.Client instead.
type Transport struct {
	// Base is the base RoundTripper used to make HTTP requests. If nil, then
	// http.DefaultTransport is used
	Base http.RoundTripper
	// source supplies the token to use when signing a request
	source TokenSource
	// signer is a configured OAuth 1 Signer
	signer *Signer
}

// RoundTrip authorizes the request with a signed OAuth1 authorization header
// using the transport token source and signer.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.source == nil {
		return nil, fmt.Errorf("oauth1: Transport's source is nil")
	}
	accessToken, err := t.source.Token()
	if err != nil {
		return nil, err
	}
	if t.signer == nil {
		return nil, fmt.Errorf("oauth1: Transport's signer is nil")
	}
	// RoundTripper should not modify the given request, clone it
	req2 := cloneRequest(req)
	err = t.signer.SetRequestAuthHeader(req2, accessToken)
	if err != nil {
		return nil, err
	}
	return t.base().RoundTrip(req2)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// cloneRequest returns a clone of the given *http.Request with a shallow
// copy of struct fields and a deep copy of the Header map.
func cloneRequest(req *http.Request) *http.Request {
	// shallow copy the struct
	r2 := new(http.Request)
	*r2 = *req
	// deep copy Header so setting a header on the clone does not affect original
	r2.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
