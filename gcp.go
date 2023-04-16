package verysign

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

const (
	keyIdTokenHeaderKey = "kid"
	gcpV1Url            = "https://www.googleapis.com/oauth2/v1/certs"
)

type gsignv1 struct {
	certs map[string]string
	sync.Mutex
}

func initGCP() (*gsignv1, error) {
	var (
		err  error
		body []byte
	)
	gs := &gsignv1{}

	if body, err = gs.getKeys(); err != nil {
		return nil, err
	}

	gs.Lock()
	defer gs.Unlock()
	err = json.Unmarshal(body, &gs.certs)
	return gs, err
}

// VerifySignature verifies the signature of a JWT token using the public RS256 key of the vendor specified in the Verifier struct.
//
// Parameters:
//   - tokenString: the JWT token to be verified.
//
// Returns:
//   - a *jwt.Token representing the parsed token if the signature is valid.
//   - an error if the signature could not be verified or the token is invalid.
//
// Example:
//   tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
//   verifier, err := verysign.Init(verysign.GCP)
//   if err != nil {
//     // handle error
//   }
//   parsedToken, err := verifier.VerifySignature(tokenString)
//   if err != nil {
//     // handle error
//   }
//   use parsedToken.Valid and parsedToken.Claims to access the token's validity and claims
func (g *gsignv1) VerifySignature(tokenString string) (*jwt.Token, error) {
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

		key, found := g.getKey(keyId)
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

func (g *gsignv1) getKey(keyID string) (string, bool) {
	g.Lock()
	key, ok := g.certs[keyID]
	g.Unlock()
	if ok {
		return key, ok
	}
	g.refreshKeys()

	g.Lock()
	defer g.Unlock()
	key, ok = g.certs[keyID]
	return key, ok
}

func (g *gsignv1) refreshKeys() {
	body, _ := g.getKeys()
	g.Lock()
	defer g.Unlock()
	_ = json.Unmarshal(body, &g.certs)
}

func (g *gsignv1) getKeys() (body []byte, err error) {
	var response *http.Response
	request, _ := http.NewRequest(http.MethodGet, gcpV1Url, nil)
	request.Header.Add("Accept", "application/json")
	client := &http.Client{}

	if response, err = client.Do(request); err != nil || response.StatusCode != 200 {
		return
	}
	defer response.Body.Close()

	if body, err = io.ReadAll(response.Body); err != nil {
		return
	}
	return
}
