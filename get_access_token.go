package oauth1

import (
	"fmt"
	"log"
)

func GetAccessToken(consumerKey, consumerSecret, oauthVerifier, baseURL string) (string, string, error) {
	config := &Config{
		ConsumerKey:    consumerKey,
		ConsumerSecret: consumerSecret,
		Endpoint: Endpoint{
			RequestTokenURL: baseURL + "/oauth/token/request",
			AccessTokenURL:  baseURL + "/oauth/token/access",
		},
		Signer: &HMAC256Signer{ConsumerSecret: consumerSecret},
	}

	token := NewToken("", "") // Empty Token and Secret (to be filled in later)

	// Create an OAuth1 client
	httpClient := config.Client(NoContext, token)

	// Get request token
	requestToken, requestSecret, err := config.RequestToken()
	if err != nil {
		log.Fatalf("Error obtaining request token: %v", err)
	}
	fmt.Printf("Request Token: %s\n", requestToken)
	fmt.Printf("Request Token Secret: %s\n", requestSecret)

	// Exchange request token and OAuth verifier for an access token
	accessToken, accessSecret, err := config.AccessToken(requestToken, requestSecret, oauthVerifier)
	if err != nil {
		log.Fatalf("Error obtaining access token: %v", err)
	}
	fmt.Printf("Access Token: %s\n", accessToken)
	fmt.Printf("Access Token Secret: %s\n", accessSecret)

	// Use the access token to make authorized API requests
	token.Token = accessToken
	token.TokenSecret = accessSecret
	httpClient = config.Client(NoContext, token)

	// Example API request
	resp, err := httpClient.Get(baseURL + "/api/rest/products")
	if err != nil {
		log.Fatalf("Error making API request: %v", err)
	}
	defer resp.Body.Close()

	return accessToken, accessSecret, nil
}
