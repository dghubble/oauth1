package oauth1

// Token is an AccessToken (token credential) which allows a consumer (client)
// to access resources from an OAuth1 provider server.
type Token struct {
	Token       string
	TokenSecret string
}

func NewToken(token, tokenSecret string) *Token {
	return &Token{
		Token:       token,
		TokenSecret: tokenSecret,
	}
}

// TokenSource can return a Token
type TokenSource interface {
	Token() (*Token, error)
}

// ReuseTokenSource is a TokenSource which wraps a Token and a TokenSource.
// It returns the token as long as it is valid, otherwise, a new Token is
// retrieved using the TokenSource (not yet implemented).
type ReuseTokenSource struct {
	token  *Token
	source TokenSource
}

func (ts *ReuseTokenSource) Token() (*Token, error) {
	return ts.token, nil
}
