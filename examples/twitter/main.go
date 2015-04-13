package main

import (
	"fmt"
	"github.com/dghubble/go-twitter/twitter"
	"github.com/dghubble/oauth1"
	"io/ioutil"
	"os"
)

func main() {
	// read credentials from environment variables
	consumerKey := os.Getenv("TWITTER_CONSUMER_KEY")
	consumerSecret := os.Getenv("TWITTER_CONSUMER_SECRET")
	accessToken := os.Getenv("TWITTER_TOKEN")
	accessTokenSecret := os.Getenv("TWITTER_TOKEN_SECRET")
	if consumerKey == "" || consumerSecret == "" || accessToken == "" || accessTokenSecret == "" {
		panic("Missing required environment variable")
	}

	config := oauth1.NewConfig(consumerKey, consumerSecret)
	token := oauth1.NewToken(accessToken, accessTokenSecret)

	// httpClient will automatically authorize http.Request's
	httpClient := config.Client(token)

	path := "https://api.twitter.com/1.1/statuses/home_timeline.json?count=2"
	resp, _ := httpClient.Get(path)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("Raw Response Body:\n%v\n", string(body))

	// Nicer: Pass OAuth1 client to go-twitter API
	api := twitter.NewClient(httpClient)
	params := &twitter.UserShowParams{ScreenName: "dghubble"}
	user, _, _ := api.Users.Show(params)
	fmt.Printf("User from go-twitter API:\n%+v\n", user)
}
