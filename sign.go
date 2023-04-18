// Package verysign provides functions for creating and verifying RS256 digital signatures for jwt tokens
// using vendor's public keys.
package verysign

import (
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

type Sign interface {
	VerifySignature(tokenString string) (*jwt.Token, error)
}

// Init initializes a new instance of the verifier struct with the appropriate vendor's public key.
//
// Parameters:
//   - vendor: the name of the vendor whose public key will be used to verify the signature.
//   - supported vendors roster: GCP
//
// Returns:
//   - a new instance of the Verifier struct.
//
// Example:
//   verifier := verysign.Init(verysign.GCP)
func Init(vendor Vendor) (Sign, error) {
	switch vendor {
	case GCP:
		return initGCP()

	default:
		return nil, fmt.Errorf("unsupported vendor: %+v. For a list o vendors check the documentation", vendor)
	}
}
