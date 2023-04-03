package verysign

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

type Sign interface {
	VerifySignature(tokenString string) (*jwt.Token, error)
}

type signv1 struct {
	certs map[string]string
}

func Init(vendor Vendor) (Sign, error) {
	if vendor != GCP {
		return nil, fmt.Errorf("unsupported vendor: %+v. For a list o vendors check the documentation", vendor)
	}
	var err error
	resp, err := http.Get(urls[vendor])
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	gs := &signv1{}
	err = json.Unmarshal(body, &gs.certs)
	return gs, err
}

func (g signv1) VerifySignature(tokenString string) (*jwt.Token, error) {
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
			return nil, fmt.Errorf("an error occurred parsing the public key base64 for key ID '%v'; this is a code bug: %+v", keyId, err.Error())
		}

		return pubKey, nil
	}

	return jwt.Parse(tokenString, verifySign)
}
