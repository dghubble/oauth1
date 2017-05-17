// Package etsy provides constants for using OAuth1 to access Etsy.
package etsy

import "github.com/dghubble/oauth1"

// Endpoint is Etsy's OAuth 1 endpoint.
var Endpoint = oauth1.Endpoint{
	RequestTokenURL: "https://openapi.etsy.com/v2/oauth/request_token?scope=transactions_r",
	// AuthorizeURL:    "https://api.xing.com/v1/authorize",
	AccessTokenURL: "https://openapi.etsy.com/v2/oauth/access_token",
}
