# verysign

## Verifying signature for RS256 signed jwt

This project validates if a jwt token was signed by a vendor that provides Oauth2 public keys (using RS256 alg) through a public endpoint (.well-know) when dealing with its APIs (i.e. GCP Cloud Tasks).

Introduce the `VerifySignature` call within you auth middleware to validate if a vendor's private key was used to sign the jwt token.

On your application initialization, use `Init` to generate the instance to verify the signature later.

List of supported vendors:

* GCP

Supported Go version: starting on 1.16

## Example using echo

```
import github.com/lndaquino/verysign

// app initialization
...
    vs, err := verysign.Init(verysign.GCP)
    // handle error
    e := echo.New()
    e.POST("/task", handleTask, Auth(vs))
...

func Auth(vs verysign.Sign) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth, err := // extract the jwt bearer token from Authorization header
			// handle error

			token, err := vs.VerifySignature(auth)
            // handle error

            // token was signed by a valid key, check token validity
            if token.Valid // ok, token is valid

            // check claims
        }
    }
}
```

## Furthers steps

* switch to use Oauth2 V3 Google endpoints

* add AWS and AZURE Oauth2 signature verification

* add claims validation

* add wrapper to echo and other web frameworks to handle it easily


## Acknowledgment

[jwt-go issues](https://github.com/dgrijalva/jwt-go/issues/438) for the useful inspirations