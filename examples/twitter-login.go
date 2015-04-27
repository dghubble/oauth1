package main

import (
	"fmt"
	"github.com/dghubble/oauth1"
	twauth "github.com/dghubble/oauth1/twitter"
	"log"
	"os"
)

const outOfBand = "oob"

var config oauth1.Config

// main performs PIN-based 3-legged auth to show the Oauth 1 user flow in a
// simple command line program.
func main() {
	// read credentials from environment variables
	consumerKey := os.Getenv("TWITTER_CONSUMER_KEY")
	consumerSecret := os.Getenv("TWITTER_CONSUMER_SECRET")
	if consumerKey == "" || consumerSecret == "" {
		log.Fatal("Required environment variable missing.")
	}

	config = oauth1.Config{
		ConsumerKey:    consumerKey,
		ConsumerSecret: consumerSecret,
		CallbackURL:    outOfBand,
		Endpoint:       twauth.AuthorizeEndpoint,
	}

	requestToken, err := login()
	if err != nil {
		log.Fatalf("Request Token Phase: %s", err.Error())
	}
	accessToken, err := receivePIN(requestToken)
	if err != nil {
		log.Fatalf("Access Token Phase: %s", err.Error())
	}

	fmt.Println("Consumer was granted an access token to act on behalf of a user.")
	fmt.Printf("token: %s\nsecret: %s\n", accessToken.Token, accessToken.TokenSecret)
}

func login() (*oauth1.RequestToken, error) {
	requestToken, err := config.GetRequestToken()
	if err != nil {
		return nil, err
	}
	authorizationURL, err := config.AuthorizationURL(requestToken)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Open this URL in your browser:\n%s\n", authorizationURL.String())
	return requestToken, err
}

func receivePIN(requestToken *oauth1.RequestToken) (*oauth1.Token, error) {
	fmt.Printf("Paste your PIN here: ")
	var verifier string
	_, err := fmt.Scanf("%s", &verifier)
	if err != nil {
		return nil, err
	}
	return config.GetAccessToken(requestToken, verifier)
}
