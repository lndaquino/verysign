# verysign 🔑✅

**Secure JWT Signature Verification for Cloud Services**

A lightweight Go package for verifying RS256-signed JWT tokens using OAuth2 public keys from trusted cloud providers.

[![Go Version](https://img.shields.io/badge/go-1.18%2B-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔒 Verify JWT signatures using vendor-provided public keys
- ☁️ Currently supports Google Cloud Platform (GCP)
- 🛡️ Middleware-ready design for web frameworks
- 🔄 Automatic key rotation handling
- ⚡ Efficient in-memory certificate caching

## Installation

```bash
go get github.com/lndaquino/verysign
```

## Quick Start

### Initialization
```go
vs, err := verysign.Init(verysign.GCP)
if err != nil {
    log.Fatal("Failed to initialize verysign:", err)
}
```

### Usage example with Echo
```go
package main

import (
    "github.com/labstack/echo/v4"
    "github.com/lndaquino/verysign"
)

func main() {
    vs, _ := verysign.Init(verysign.GCP)
    e := echo.New()
    
    // Protected route with signature verification
    e.POST("/tasks", handleTask, AuthMiddleware(vs))
    e.Start(":8080")
}

func AuthMiddleware(vs verysign.Sign) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            // Extract token from Authorization header
            tokenString := extractToken(c.Request())
            
            // Verify token signature
            parsedToken, err := vs.VerifySignature(tokenString)
            if err != nil {
                return c.JSON(401, map[string]string{"error": "invalid signature"})
            }
            
            // Validate token claims
            if !parsedToken.Valid {
                return c.JSON(401, map[string]string{"error": "expired token"})
            }
            
            // Store validated claims in context
            c.Set("user", parsedToken.Claims)
            
            return next(c)
        }
    }
}

func extractToken(r *http.Request) string {
    // Your token extraction logic here
}
```


## Supported Vendors

| Provider | Status |
|----------|--------|
| Google Cloud Platform (GCP) | ✅ Implemented |
| AWS | 🚧 Planned |
| Azure | 🚧 Planned |

## Roadmap

- [x] GCP Public Key Integration
- [ ] Migrate to Google OAuth2 V3 endpoints
- [ ] Add AWS support
- [ ] Add Azure support
- [ ] Built-in claims validation
- [ ] Framework-specific middleware packages
- [ ] Custom certificate refresh intervals

## Security Considerations

- Always validate token expiration (`parsedToken.Valid`)
- Verify token claims match your expectations
- Use HTTPS in production environments
- Rotate credentials according to vendor recommendations

## Why verysign?

When working with cloud services that send signed requests:
1. 🔍 Verifies requests actually come from your trusted vendor
2. 🛡️ Prevents spoofed API requests
3. ⏱️ Automatically handles key rotation
4. 🔄 Standardized validation across cloud providers

## Acknowledgements

This package was inspired by community discussions around secure JWT validation:
- [JWT-Go Issue #438](https://github.com/dgrijalva/jwt-go/issues/438) - Key insights into secure JWT validation patterns

---

**Found this useful?** Please consider starring the repository and contributing to future development!
