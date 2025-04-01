# echo-secure [![Go Report Card](https://goreportcard.com/badge/github.com/alexferl/echo-secure)](https://goreportcard.com/report/github.com/alexferl/echo-secure) [![codecov](https://codecov.io/gh/alexferl/echo-secure/branch/master/graph/badge.svg)](https://codecov.io/gh/alexferl/echo-secure)

A [JWT](https://jwt.io/) middleware for the [Echo](https://github.com/labstack/echo) framework using
[lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

## Motivation
You might wonder why not use the JWT middleware that ships with Echo?

## Installing
```shell
go get github.com/alexferl/echo-secure
```

## Using
### Code example
```go
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/alexferl/echo-secure"
)

func main() {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	e.Use(secure.Secure())

	e.Logger.Fatal(e.Start("localhost:1323"))
}
```

Getting a token:
```shell
curl -X POST http://localhost:1323/login\?name\=alex
{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj..."}
```

### Configuration
```go

```
