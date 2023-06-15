package oauth1

import (
	"fmt"
	"net/http"
	"net/http/httputil"
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
		fmt.Errorf("Error obtaining request token: %v", err)
	}
	fmt.Printf("Request Token: %s\n", requestToken)
	fmt.Printf("Request Token Secret: %s\n", requestSecret)

	// Exchange request token and OAuth verifier for an access token
	accessToken, accessSecret, err := config.AccessToken(requestToken, requestSecret, oauthVerifier)
	if err != nil {
		fmt.Errorf("Error obtaining access token: %v", err.Error())
	}
	fmt.Printf("Access Token: %s\n", accessToken)
	fmt.Printf("Access Token Secret: %s\n", accessSecret)

	// Use the access token to make authorized API requests
	token.Token = accessToken
	token.TokenSecret = accessSecret
	httpClient = config.Client(NoContext, token)

	// Example API request
	resp, err := httpClient.Get(baseURL + "/rest/V1/store/storeConfigs")
	if err == nil {
		prettyPrintHTTPResponse(resp)
	} else {
		fmt.Errorf("Error making API request: %v", err.Error())
	}
	defer resp.Body.Close()

	return accessToken, accessSecret, nil
}

func prettyPrintHTTPResponse(response *http.Response) {
	// Dump the response as a byte slice
	dump, err := httputil.DumpResponse(response, true)
	if err != nil {
		fmt.Println("Failed to dump response:", err)
		return
	}

	// Print the formatted response
	fmt.Println(string(dump))
}
