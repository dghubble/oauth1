package oauth1

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	_ Verifier = &RSAVerifier{}
	_ Verifier = &HMACVerifier{}
)

const (
	rsaKey = `MIIEowIBAAKCAQEAy45DIEXPGTM/h3DC4GJKN+7k1wyZo5VpMGjESRkmq2RJOW+CJ8dlqcir4COX9wQlvmIZKSD/UDuai9zTXs3yHm1CizrOmF4PE0xxC8kNUvQccffBImoWLLzFs0sJHk/r0GNByTh+glQZksXhOhIaFETDPG/04MdwppvKDIC8him4dhQSNtf+5B62tvR1vmSaiUIq16twOYqDRAxZNEJ+SQ6d4uubDfQzIvQDGxgSi50WFcuNGdlzZgQpKYofC5lci06QoHV145yDMhl429Oj6urgcSX9kmypRa2PAWSRo7hmPp/siFHDk9OS3pLlOuWkVfNpMTJ8pbN+1quyHW/0OwIDAQABAoIBAFszUyn7fQ2KY5VYVUfZYe1rkIY1dATR5X42AnPJ3ASAezpLlqIh+Y+3hCJ5cBXReuOw6hr+WMXm3ph5iQ558VfmliDxaSzlP5Xi8udX3itjifcaDSNRKrxCm8V4Ag7dugb04b25HR1hds/G7uFoyNx57ot+kdXAJd3QARfW+iCVdffnsLEl4osUJkNMYb75cqv51BWRt3nzkNXXBv5GRfywZMIuuRdp090eyqkgq6giofVLiuCcyJEMQuDAY/wo/np49wC+W2LMdOgZpqgmxnS7SHEMBtAbuh1mCccHS3sa3XOBPuC6kKs6kmJm85Xu+qnOn6qLTJQVs4xUhbz/BYECgYEA2j8mKlhT6UNmOVuSC7BkMPBupdBFWVjI2gbMDwIkEQ3vL+Q4sdqNJM1x6EubyXApWK/t3HmMYcSJ8ug1BH5T3FRTOeAkKiWmdI21NaHsgj2mOldJOVTYluDUVUE+5DvSHCZgIRpg9qDxu0eCrMimcoXrn5Et3xJeIrw6fo5Q0HsCgYEA7sSJlgNWcjElAVv0SEj2fDmAxbLtarVzmRAgJ7G4R2tZliofDWGVvavb2rsFODHzsOnpTSopBDknYyNAXWQ1LtvaRjt4qJecLChx+pXy05BTPfTJlBZbq5N7cscERcQe0KbyYVE+jF0+yMTZidfAOzIO6A0PX38shpaKQfUaf0ECgYAIf50E2RurYayBX0d4nQ3JuhMU8d9Bc2ue0dTwYKz23QwLWV+7zT7hx/4/hXIzjeKOSYuBoloNFJIqm1A1NJYfZkk3X7sIyR6KO1prFDsZdz0Z2HxJdzxX47lg+IFyccHkxrnHkDdmYy4GlOpJwCZ7HyvlssmOfjCcOagtdW1AMQKBgBUySWyR20jD6B8YxLTuFUOt7yqd2cnRVfPOpKwhcNSWSRu1nZAYi6yM5zWhyLLWbGXWPinlhkKjuEVqyboAvV/tkJEPkoSVAP5CkOvICAiUFW+4nXSSD41JyHnGBTEUWg/34iiVh9H6LSqxnwZHqv8WUJB1KFo39gH0t01nrvSBAoGBAMY8PqRGcqQzBVwPrFgQDpXzQT1kgdK9/Z+ou5m2laozMqzCzoMtMZwTK25BPXOu1c93EeFBP/V7JP1glWfHulBXNWXRm0qkNDQeTzRwDkB4Nqu9chbaDRSSwtWa+k93nHNiWqUfn8/XhU+b5mM6ObonlhM7QrffwH3o8Obpw34n`
)

func TestMakeURLAbs_NoHeader(t *testing.T) {
	req := http.Request{}
	req.Host = "www.example.com"
	req.URL = &url.URL{}
	NewVerifierManager(nil, "default-scheme", -1).makeURLAbs(&req)
	assert.Equal(t, req.Host, req.URL.Host)
	assert.Equal(t, "default-scheme", req.URL.Scheme)
}

func TestMakeURLAbs_WithForwardedHeader(t *testing.T) {
	req := http.Request{}
	req.Host = "www.example.com"
	req.URL = &url.URL{}
	req.Header = make(http.Header)
	req.Header.Set("Forwarded", `for="127.0.0.1";proto=https`)
	NewVerifierManager(nil, "default-scheme", -1).makeURLAbs(&req)
	assert.Equal(t, req.Host, req.URL.Host)
	assert.Equal(t, "https", req.URL.Scheme)
}

func TestMakeURLAbs_WithXForwardedProtoHeader(t *testing.T) {
	req := http.Request{}
	req.Host = "www.example.com"
	req.URL = &url.URL{}
	req.Header = make(http.Header)
	req.Header.Set("X-Forwarded-Proto", `https`)
	NewVerifierManager(nil, "default-scheme", -1).makeURLAbs(&req)
	assert.Equal(t, req.Host, req.URL.Host)
	assert.Equal(t, "https", req.URL.Scheme)
}

func TestCollectRequestParameters(t *testing.T) {
	// example from TestCollectParameters
	values := url.Values{}
	values.Add("c2", "")
	values.Add("plus", "2 q")
	req, err := http.NewRequest("POST", "/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", strings.NewReader(values.Encode()))
	assert.NoError(t, err)
	req.Header.Set(contentType, formContentType)
	req.Header.Set(authorizationHeaderParam, `OAuth realm="Example", oauth_consumer_key="9djdj82h48djs9d2", oauth_token="kkk9d7dh3k39sjv7", oauth_signature_method="HMAC-SHA1", oauth_timestamp="137131201", oauth_nonce="7d8f3e4a", oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"`)

	params, signature, err := collectRequestParameters(req)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"b5":                     "=%3D",
		"a3":                     "a",
		"c@":                     "",
		"a2":                     "r b",
		"oauth_token":            "kkk9d7dh3k39sjv7",
		"oauth_consumer_key":     "9djdj82h48djs9d2",
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_timestamp":        "137131201",
		"oauth_nonce":            "7d8f3e4a",
		"c2":                     "",
		"plus":                   "2 q",
	}, params)
	assert.Equal(t, `djosJKDKJSD8743243/jdk33klY=`, signature)
}

func TestVerifier_RSA(t *testing.T) {
	// example from TestCollectParameters
	values := url.Values{}
	values.Add("c2", "")
	values.Add("plus", "2 q") // duplicate keys not supported, a3 -> plus
	req, err := http.NewRequest("POST", "http://127.0.0.1:50428/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", strings.NewReader(values.Encode()))
	assert.NoError(t, err)
	req.Header.Set(contentType, formContentType)
	req.Header.Set(authorizationHeaderParam, `OAuth oauth_consumer_key="consumer_key", oauth_nonce="6hrVr5eVPa5cWUtnW3sRIMlti2uB0zM43pk9mYIggFY%3D", oauth_signature="Nu%2B7FzqMw%2B18w6%2BzcT45SjWBXWjvf%2FW8adgIpgNahfZGzSExrIA6YRugfngCD97t4ms%2B4Vo2ozPOYHhxq%2BIF3EqoSdno5v53rA9mBvOmNU9XKr7gb92F0MVw%2F6M8MQUhputsUW4L7JixEXHymQUEub82ZC58xHJHklPUNIUtmyuxpzeII7E2K09KLMDp9%2F4ne%2FIm%2FufSoWDCBWn9497SIYZKNGyDAHav9zuXFy8x%2FItwknSpvSGG5zr1j2OyaZz7P5AIHVYPryi1N0Mwu35QHES4pafc0z1Z%2Fgm8PMvcI2BofqdEHbs65okhrE%2BSCxPRqJtc1k4A5LkmWbyp91WqHw%3D%3D", oauth_signature_method="RSA-SHA1", oauth_timestamp="1659497715", oauth_token="", oauth_version="1.0"`)

	err = NewVerifierManager(func(consumerKey, method string, params map[string]string) (Verifier, error) {
		assert.Equal(t, "consumer_key", consumerKey)
		assert.Equal(t, "RSA-SHA1", method)

		b, err := base64.StdEncoding.DecodeString(rsaKey)
		require.NoError(t, err)
		k, err := x509.ParsePKCS1PrivateKey(b)
		require.NoError(t, err)
		return NewRSAVerifier(&k.PublicKey, crypto.SHA1), nil
	}, "", -1).Verify(req)
	require.NoError(t, err)
}

func TestVerifier_InvalidRSA(t *testing.T) {
	// example from TestCollectParameters
	cases := []string{
		// invalid signature
		// first N -> n
		"nu%2B7FzqMw%2B18w6%2BzcT45SjWBXWjvf%2FW8adgIpgNahfZGzSExrIA6YRugfngCD97t4ms%2B4Vo2ozPOYHhxq%2BIF3EqoSdno5v53rA9mBvOmNU9XKr7gb92F0MVw%2F6M8MQUhputsUW4L7JixEXHymQUEub82ZC58xHJHklPUNIUtmyuxpzeII7E2K09KLMDp9%2F4ne%2FIm%2FufSoWDCBWn9497SIYZKNGyDAHav9zuXFy8x%2FItwknSpvSGG5zr1j2OyaZz7P5AIHVYPryi1N0Mwu35QHES4pafc0z1Z%2Fgm8PMvcI2BofqdEHbs65okhrE%2BSCxPRqJtc1k4A5LkmWbyp91WqHw%3D%3D",
		// not percent encoded
		"Nu%%B7FzqMw%2B18w6%2BzcT45SjWBXWjvf%2FW8adgIpgNahfZGzSExrIA6YRugfngCD97t4ms%2B4Vo2ozPOYHhxq%2BIF3EqoSdno5v53rA9mBvOmNU9XKr7gb92F0MVw%2F6M8MQUhputsUW4L7JixEXHymQUEub82ZC58xHJHklPUNIUtmyuxpzeII7E2K09KLMDp9%2F4ne%2FIm%2FufSoWDCBWn9497SIYZKNGyDAHav9zuXFy8x%2FItwknSpvSGG5zr1j2OyaZz7P5AIHVYPryi1N0Mwu35QHES4pafc0z1Z%2Fgm8PMvcI2BofqdEHbs65okhrE%2BSCxPRqJtc1k4A5LkmWbyp91WqHw%3D%3D",
		// not base64 encoded
		// last = is replaced
		"Nu%2B7FzqMw%2B18w6%2BzcT45SjWBXWjvf%2FW8adgIpgNahfZGzSExrIA6YRugfngCD97t4ms%2B4Vo2ozPOYHhxq%2BIF3EqoSdno5v53rA9mBvOmNU9XKr7gb92F0MVw%2F6M8MQUhputsUW4L7JixEXHymQUEub82ZC58xHJHklPUNIUtmyuxpzeII7E2K09KLMDp9%2F4ne%2FIm%2FufSoWDCBWn9497SIYZKNGyDAHav9zuXFy8x%2FItwknSpvSGG5zr1j2OyaZz7P5AIHVYPryi1N0Mwu35QHES4pafc0z1Z%2Fgm8PMvcI2BofqdEHbs65okhrE%2BSCxPRqJtc1k4A5LkmWbyp91WqHw%3D%3A",
	}
	for _, signature := range cases {
		values := url.Values{}
		values.Add("c2", "")
		values.Add("plus", "2 q") // duplicate keys not supported, a3 -> plus
		req, err := http.NewRequest("POST", "http://127.0.0.1:50428/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", strings.NewReader(values.Encode()))
		assert.NoError(t, err)
		req.Header.Set(contentType, formContentType)
		header := `OAuth oauth_consumer_key="consumer_key", oauth_nonce="6hrVr5eVPa5cWUtnW3sRIMlti2uB0zM43pk9mYIggFY%3D", oauth_signature="` + signature + `", oauth_signature_method="RSA-SHA1", oauth_timestamp="1659497715", oauth_token="", oauth_version="1.0"`
		req.Header.Set(authorizationHeaderParam, header)

		err = NewVerifierManager(func(consumerKey, method string, params map[string]string) (Verifier, error) {
			assert.Equal(t, "consumer_key", consumerKey)
			assert.Equal(t, "RSA-SHA1", method)

			b, err := base64.StdEncoding.DecodeString(rsaKey)
			require.NoError(t, err)
			k, err := x509.ParsePKCS1PrivateKey(b)
			require.NoError(t, err)
			return NewRSAVerifier(&k.PublicKey, crypto.SHA1), nil
		}, "", -1).Verify(req)
		require.Error(t, err)
	}
}

func TestVerifier_HMACSHA1_WithoutOAuthToken(t *testing.T) {
	// example from TestCollectParameters
	values := url.Values{}
	values.Add("c2", "")
	values.Add("plus", "2 q")
	req, err := http.NewRequest("POST", "http://127.0.0.1:51060/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", strings.NewReader(values.Encode()))
	assert.NoError(t, err)
	req.Header.Set(contentType, formContentType)
	req.Header.Set(authorizationHeaderParam, `OAuth oauth_consumer_key="9djdj82h48djs9d2", oauth_nonce="UrmFlgNMjd2UF8sodAzDPqN5AylKo33kxF9gqnd1j7E%3D", oauth_signature="4ZYe7rg2We2jgfv20ZNqlVbCibY%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1659507521", oauth_token="", oauth_version="1.0"`)

	err = NewVerifierManager(func(consumerKey, method string, params map[string]string) (Verifier, error) {
		assert.Equal(t, "9djdj82h48djs9d2", consumerKey)
		assert.Equal(t, "HMAC-SHA1", method)
		return NewHMACVerifier(NewConfig("9djdj82h48djs9d2", "j49sk3j29djd"), ""), nil
	}, "", -1).Verify(req)
	require.NoError(t, err)
}

func TestVerifier_HMACSHA1_WithOAuthToken(t *testing.T) {
	// example from TestCollectParameters
	values := url.Values{}
	values.Add("c2", "")
	values.Add("plus", "2 q")
	req, err := http.NewRequest("POST", "/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", strings.NewReader(values.Encode()))
	assert.NoError(t, err)
	req.Header.Set(contentType, formContentType)
	req.Header.Set(authorizationHeaderParam, `OAuth oauth_consumer_key="9djdj82h48djs9d2", oauth_nonce="FnwtgC3exdLhc2Kspuc9GYPhGzgyQEB1T5tRcfM2FtM%3D", oauth_signature="6F8L5pN4iERKpwRqfuMGA9WesYU%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1659507394", oauth_token="kkk9d7dh3k39sjv7", oauth_version="1.0"`)
	req.Header.Set("Forwarded", `for="127.0.0.1:51043";proto=http`)
	req.Host = "127.0.0.1:51043"

	err = NewVerifierManager(func(consumerKey, method string, params map[string]string) (Verifier, error) {
		assert.Equal(t, "9djdj82h48djs9d2", consumerKey)
		assert.Equal(t, "HMAC-SHA1", method)
		return NewHMACVerifier(NewConfig("9djdj82h48djs9d2", "j49sk3j29djd"), "dh893hdasih9"), nil
	}, "", -1).Verify(req)
	require.NoError(t, err)
}

func TestVerifier_InvalidHMACSHA1(t *testing.T) {
	// example from TestCollectParameters
	values := url.Values{}
	values.Add("c2", "")
	values.Add("plus", "2 q")
	req, err := http.NewRequest("POST", "http://127.0.0.1:51060/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", strings.NewReader(values.Encode()))
	assert.NoError(t, err)
	req.Header.Set(contentType, formContentType)
	req.Header.Set(authorizationHeaderParam, `OAuth oauth_consumer_key="9djdj82h48djs9d2", oauth_nonce="UrmFlgNMjd2UF8sodAzDPqN5AylKo33kxF9gqnd1j7E%3D", oauth_signature="3ZYe7rg2We2jgfv20ZNqlVbCibY%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1659507521", oauth_token="", oauth_version="1.0"`)

	err = NewVerifierManager(func(consumerKey, method string, params map[string]string) (Verifier, error) {
		assert.Equal(t, "9djdj82h48djs9d2", consumerKey)
		assert.Equal(t, "HMAC-SHA1", method)
		return NewHMACVerifier(NewConfig("9djdj82h48djs9d2", "j49sk3j29djd"), ""), nil
	}, "", -1).Verify(req)
	require.Error(t, err)
}

func TestVerifier_TooOld(t *testing.T) {
	// example from TestCollectParameters
	values := url.Values{}
	values.Add("c2", "")
	values.Add("plus", "2 q")
	req, err := http.NewRequest("POST", "/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", strings.NewReader(values.Encode()))
	assert.NoError(t, err)
	req.Header.Set(contentType, formContentType)
	req.Header.Set(authorizationHeaderParam, `OAuth oauth_consumer_key="9djdj82h48djs9d2", oauth_nonce="FnwtgC3exdLhc2Kspuc9GYPhGzgyQEB1T5tRcfM2FtM%3D", oauth_signature="6F8L5pN4iERKpwRqfuMGA9WesYU%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1659507394", oauth_token="kkk9d7dh3k39sjv7", oauth_version="1.0"`)
	req.Header.Set("Forwarded", `for="127.0.0.1:51043";proto=http`)
	req.Host = "127.0.0.1:51043"

	err = NewVerifierManager(func(consumerKey, method string, params map[string]string) (Verifier, error) {
		assert.Equal(t, "9djdj82h48djs9d2", consumerKey)
		assert.Equal(t, "HMAC-SHA1", method)
		return NewHMACVerifier(NewConfig("9djdj82h48djs9d2", "j49sk3j29djd"), "dh893hdasih9"), nil
	}, "", time.Hour).Verify(req)
	require.Error(t, err)
}

func TestVerifier_RejectedByGetVerifier(t *testing.T) {
	// example from TestCollectParameters
	values := url.Values{}
	values.Add("c2", "")
	values.Add("plus", "2 q")
	req, err := http.NewRequest("POST", "/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", strings.NewReader(values.Encode()))
	assert.NoError(t, err)
	req.Header.Set(contentType, formContentType)
	req.Header.Set(authorizationHeaderParam, `OAuth oauth_consumer_key="9djdj82h48djs9d2", oauth_nonce="FnwtgC3exdLhc2Kspuc9GYPhGzgyQEB1T5tRcfM2FtM%3D", oauth_signature="6F8L5pN4iERKpwRqfuMGA9WesYU%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1659507394", oauth_token="kkk9d7dh3k39sjv7", oauth_version="1.0"`)
	req.Header.Set("Forwarded", `for="127.0.0.1:51043";proto=http`)
	req.Host = "127.0.0.1:51043"

	err = NewVerifierManager(func(consumerKey, method string, params map[string]string) (Verifier, error) {
		return nil, fmt.Errorf("fail to get verifier")
	}, "", -1).Verify(req)
	require.Error(t, err)
}
