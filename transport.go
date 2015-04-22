package oauth1

import (
	"net/http"
)

// Transport is an http.RoundTripper which makes OAuth1 HTTP requests.
// It signs requests using the Signer config and Token from the TokenSource
// and adds an Authorization header.
type Transport struct {
	source TokenSource
	signer *Signer
}

// RoundTrip OAuth1 signs the request with the source's access token and sets
// the authorization header.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	accessToken, err := t.source.Token()
	if err != nil {
		return nil, err
	}
	err = t.signer.SetRequestAuthHeader(req, accessToken)
	if err != nil {
		return nil, err
	}
	// TODO: request mutation violates http.RoundTripper recommendations
	res, err := http.DefaultTransport.RoundTrip(req)
	return res, err
}
