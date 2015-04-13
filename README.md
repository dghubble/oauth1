
# OAuth1 [![Build Status](https://travis-ci.org/dghubble/oauth1.png)](https://travis-ci.org/dghubble/oauth1) [![GoDoc](http://godoc.org/github.com/dghubble/oauth1?status.png)](http://godoc.org/github.com/dghubble/oauth1)

OAauth1 is a Go client implementation of the OAuth1 spec. It supports authorizing HTTP requests. 

The OAuth1 package takes design cues from the [golang.org/x/oauth2](https://godoc.org/golang.org/x/oauth2), providing an http.Client which handles signing requests and authorization via a custom Transport.

If an official oauth1 package were to be developed by the Go authors, I'd recommend you use that implementation instead. However, at this time, no official implementation exists.

## Note

This library is currently under development. It provides a signing http.Client, but does not yet completely implement the spec or handle credential retrieval from a provider backend.

## Install

    go get github.com/dghubble/oauth1

## Documentation

Read [GoDoc](https://godoc.org/github.com/dghubble/oauth1)

## Usage

Create an application `Config` with a `ConsumerKey` and `ConsumerSecret`. Obtain a token credential in some way (many providers offer a web interface or command line tool for this) and create a `Token`.

```go
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


