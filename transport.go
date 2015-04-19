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

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	accessToken, _ := t.source.Token()
	t.signer.SetRequestAuthHeader(req, accessToken)
	// TODO: request mutation violates http.RoundTripper recommendations
	res, err := http.DefaultTransport.RoundTrip(req)
	return res, err
}
