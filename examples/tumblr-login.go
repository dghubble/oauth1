package main

import (
	"fmt"
	"log"
	"os"

	"github.com/dghubble/oauth1"
	"github.com/dghubble/oauth1/tumblr"
)

var config oauth1.Config

// main performs the Tumblr OAuth1 user flow from the command line
func main() {
	// read credentials from environment variables
	consumerKey := os.Getenv("TUMBLR_CONSUMER_KEY")
	consumerSecret := os.Getenv("TUMBLR_CONSUMER_SECRET")
	if consumerKey == "" || consumerSecret == "" {
		log.Fatal("Required environment variable missing.")
	}

	config = oauth1.Config{
		ConsumerKey:    consumerKey,
		ConsumerSecret: consumerSecret,
		// Tumblr does not support oob, uses consumer registered callback
		CallbackURL: "",
		Endpoint:    tumblr.Endpoint,
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
	fmt.Printf("Choose whether to grant the application access.\nPaste " +
		"the oauth_verifier parameter (excluding trailing #_=_) from the " +
		"address bar: ")
	var verifier string
	_, err := fmt.Scanf("%s", &verifier)
	if err != nil {
		return nil, err
	}
	return config.GetAccessToken(requestToken, verifier)
}
