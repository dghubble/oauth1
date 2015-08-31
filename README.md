
# OAuth1 [![Build Status](https://travis-ci.org/dghubble/oauth1.png)](https://travis-ci.org/dghubble/oauth1) [![Coverage](http://gocover.io/_badge/github.com/dghubble/oauth1)](http://gocover.io/github.com/dghubble/oauth1) [![GoDoc](http://godoc.org/github.com/dghubble/oauth1?status.png)](http://godoc.org/github.com/dghubble/oauth1)

OAauth1 is a Go implementation of the [OAuth 1 spec](https://tools.ietf.org/html/rfc5849).

It allows end-users to authorize a client (consumer) to access protected resources on their behalf (e.g. login) and allows clients to make signed and authorized requests on behalf of a user (e.g. API calls).

It takes design cues from [golang.org/x/oauth2](https://godoc.org/golang.org/x/oauth2), providing an `http.Client` which handles request signing and authorization.

## Install

    go get github.com/dghubble/oauth1

## Documentation

Read [GoDoc](https://godoc.org/github.com/dghubble/oauth1)

### Authorization Flow

Perform the OAuth 1 authorization flow to ask a user to grant an application access to his/her resources via an access token.

```go
import (
    "github.com/dghubble/oauth1"
    "github.com/dghubble/oauth1/twitter""
)
...

config := oauth1.Config{
    ConsumerKey:    "consumerKey",
    ConsumerSecret: "consumerSecret",
    CallbackURL:    "http://mysite.com/oauth/twitter/callback",
    Endpoint:       twitter.AuthorizeEndpoint,
}
```

1. When a user performs an action (e.g. "Login with X" button calls "/login" route) get an OAuth1 request token (temporary credentials).

    ```go
    requestToken, requestSecret, err = config.RequestToken()
    // handle err
    ```

2. Obtain authorization from the user by redirecting them to the OAuth1 provider's authorization URL to grant the application access.

    ```go
    authorizationURL, err := config.AuthorizationURL(requestToken)
    // handle err
    http.Redirect(w, req, authorizationURL.String(), htt.StatusFound)
    ```

    Receive the callback from the OAuth1 provider in a handler.

    ```
    requestToken, verifier, err := oauth1.ParseAuthorizationCallback(req)
    // handle err
    ```

3. Acquire the access token (token credentials) which can later be used to make requests on behalf of the user.

    ```go
    accessToken, accessSecret, err := config.AccessToken(requestToken, requestSecret, verifier)
    // handle error
    token := NewToken(accessToken, accessSecret)
    ```

Check the [examples](examples) to see this authorization flow in action from the command line, with Twitter PIN-based login and Tumblr login.

### Authorized Requests

Use an access `Token` to make authorized requests on behalf of a user.

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

Check the [examples](examples) to see Twitter and Tumblr requests in action.

## Higher Level Packages

To implement "Login with X", you may wish to use the [gologin](https://github.com/dghubble/gologin) packages which provide login handlers for OAuth1 and OAuth2 providers.

To make requests, you may wish to use the Twitter and Tumblr Go API clients.

* [github.com/dghubble/go-twitter](https://github.com/dghubble/go-twitter)
* [github.com/benfb/go-tumblr](https://github.com/benfb/go-tumblr)

### Components

An `Endpoint` groups an OAuth provider's token and authorization URLs.Endpoints for common providers are provided in subpackages.

A `Config` stores a consumer application's consumer key and secret, the callback URL, and the Endpoint to which the consumer is registered. It provides OAuth1 authorization flow methods.

An OAuth1 `Token` is an access token which allows requests to be made as a particular user. See [Authorized Requests](#Authorized Requests) for details.

If you've used [golang.org/x/oauth2](https://godoc.org/golang.org/x/oauth2) before, this organization is similar.

## Contributing

See the [Contributing Guide](https://gist.github.com/dghubble/be682c123727f70bcfe7).

## License

[MIT License](LICENSE)
