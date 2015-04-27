
# examples

## Twitter

### Login Flow (PIN)

A consumer application can obtain a Twitter Access Token for a user by requesting the user grant access via [3-legged](https://dev.twitter.com/oauth/3-legged) or [PIN-based](https://dev.twitter.com/oauth/pin-based) OAuth 1. 

    export TWITTER_CONSUMER_KEY=xxx
    export TWITTER_CONSUMER_SECRET=yyy

    go run twitter-login.go

    Open this URL in your browser:
    https://api.twitter.com/oauth/authenticate?oauth_token=xxx
    Paste your PIN here: ddddddd
    Consumer was granted an access token to act on behalf of a user.
    token: ddddd-xxxxx
    secret: yyyyyy

Note that website backends should define a CallbackURL which can receive a verifier string and request an access token, "oob" is for PIN-based agents such as the command line.

The OAuth 1 flow can be used to implement Sign in with Twitter if receipt of an access token by your server is used to gate creation of some form of unforgeable session state. Consider using the [go-twitter](https://github.com/dghubble/go-twitter) `login` package if you're implementing Sign in with Twitter in Go.

### Authorized Requests

Use an Access Token to make requests on behalf of a Twitter user.

    export TWITTER_CONSUMER_KEY=xxx
    export TWITTER_CONSUMER_SECRET=yyy
    export TWITTER_ACCESS_TOKEN=xxx
    export TWITTER_ACCESS_TOKEN_SECRET=yyy

Run to perform requests as the user (reads only, it won't tweet anything)

    go run twitter-request.go




