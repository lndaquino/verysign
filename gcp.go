package verysign

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

const (
	keyIdTokenHeaderKey = "kid"
	gcpV1Url            = "https://www.googleapis.com/oauth2/v1/certs"
)

type gsignv1 struct {
	certs map[string]string
}

func initGCP() (*gsignv1, error) {
	var err error
	request, _ := http.NewRequest(http.MethodGet, gcpV1Url, nil)
	request.Header.Add("Accept", "application/json")
	client := &http.Client{}

	response, err := client.Do(request)
	if err != nil || response.StatusCode != 200 {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	gs := &gsignv1{}
	err = json.Unmarshal(body, &gs.certs)
	return gs, err
}

func (g gsignv1) VerifySignature(tokenString string) (*jwt.Token, error) {
	verifySign := func(token *jwt.Token) (interface{}, error) {
		var err error
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		untypedKeyId, found := token.Header[keyIdTokenHeaderKey]
		if !found {
			return nil, fmt.Errorf("no key ID key '%v' found in token header", keyIdTokenHeaderKey)
		}

		keyId, ok := untypedKeyId.(string)
		if !ok {
			return nil, fmt.Errorf("found key ID, but value was not a string")
		}

		key, found := g.certs[keyId]
		if !found {
			return nil, fmt.Errorf("no public RSA key found corresponding to key ID from token '%v'", keyId)
		}

		pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("an error occurred parsing the public key base64 for key ID '%v'; %+v", keyId, err.Error())
		}

		return pubKey, nil
	}

	return jwt.Parse(tokenString, verifySign)
}
