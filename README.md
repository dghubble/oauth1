
# OAuth1 [![Build Status](https://travis-ci.org/dghubble/oauth1.png)](https://travis-ci.org/dghubble/oauth1) [![GoDoc](http://godoc.org/github.com/dghubble/oauth1?status.png)](http://godoc.org/github.com/dghubble/oauth1)

OAauth1 is a Go implementation of the [OAuth 1 spec](https://tools.ietf.org/html/rfc5849).

It takes design cues from [golang.org/x/oauth2](https://godoc.org/golang.org/x/oauth2), providing an `http.Client` which handles authorization and signing.

## Install

    go get github.com/dghubble/oauth1

## Documentation

Read [GoDoc](https://godoc.org/github.com/dghubble/oauth1)

### Components

An `Endpoint` groups an OAuth provider's URLs for getting a request token, allowing users to authorize applications, and getting access tokens. Endpoints for common providers like [twitter](twitter) and [dropbox](dropbox) are provided in subpackages.

A `Config` stores a consumer application's consumer key and secret, the callback URL, and the Endpoint to which the consumer is registered. It provides OAuth 1 authorization flow methods and a `Client(token *Token)` method which returns an `http.Client` which will transparently authorize requests.

An OAuth1 `Token` is an access token which allows requests to be made as a particular user. It has fields `Token` and `TokenSecret`. If you already have an access token, skip to [Authorized Requests](#Authorized Requests).

If you've used [golang.org/x/oauth2](https://godoc.org/golang.org/x/oauth2) before, this organization is similar.

### Authorization Flow

The OAuth 1 authorization flow to request that a user grant an application access to his/her account (via an access token) typically looks like:

* User visits Consumer's "/login" route (via "Login with Provider" button)
* Login handler calls `config.GetRequestToken()`
* Login handler redirects user to `config.AuthorizationURL(rt *RequestToken)`
* Provider calls Consumer's CallbackURL with a `verifier`
* `config.GetAccessToken(rt *RequestToken, verifier string)`
* Consumer application stores access token. Optionally creates some form of unforgeable session state.

For more details, see the Twitter PIN-based login [example](examples) or the 
[go-twitter](https://github.com/dghubble/go-twitter) `login` package.

### Authorized Requests

After an access `Token` has been obtained, authorized requests can be made on behalf of the user.

```go
import (
    "github.com/dghubble/oauth1"
)

func main() {
    config := oauth1.NewConfig("consumerKey", "consumerSecret")
    token := oauth1.NewToken("token", "tokenSecret")

    // httpClient will automatically authorize http.Request's
    httpClient := config.Client(token)

    // example Twitter API request
    path := "https://api.twitter.com/1.1/statuses/home_timeline.json?count=2"
    resp, _ := httpClient.Get(path)
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    fmt.Printf("Raw Response Body:\n%v\n", string(body))
}
```

See more request [examples](examples).


