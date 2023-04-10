package verysign

import (
	"fmt"

	jwt "gopkg.in/dgrijalva/jwt-go.v3"
)

type Sign interface {
	VerifySignature(tokenString string) (*jwt.Token, error)
}

func Init(vendor Vendor) (Sign, error) {
	switch vendor {
	case GCP:
		return initGCP()

	default:
		return nil, fmt.Errorf("unsupported vendor: %+v. For a list o vendors check the documentation", vendor)
	}
}
