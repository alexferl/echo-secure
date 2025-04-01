# echo-secure [![Go Report Card](https://goreportcard.com/badge/github.com/alexferl/echo-secure)](https://goreportcard.com/report/github.com/alexferl/echo-secure) [![codecov](https://codecov.io/gh/alexferl/echo-secure/branch/master/graph/badge.svg)](https://codecov.io/gh/alexferl/echo-secure)

A security headers middleware for the [Echo](https://github.com/labstack/echo) framework.

## Installing
```shell
go get github.com/alexferl/echo-secure
```

## Using
### Code example
```go
package main

import (
	"net/http"

	"github.com/alexferl/echo-secure"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	e.Use(secure.New())

	e.Logger.Fatal(e.Start("localhost:1323"))
}
```

```shell
http http://127.0.0.1:1323
HTTP/1.1 200 OK
Content-Length: 2
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self';
Content-Type: text/plain; charset=UTF-8
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Date: Tue, 01 Apr 2025 02:17:23 GMT
Permissions-Policy: accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

ok
```

### Configuration
```go
// StrictTransportSecurity defines the parameters for HTTP Strict Transport Security (HSTS).
// HSTS instructs browsers to only use HTTPS for the domain of the issuing host.
type StrictTransportSecurity struct {
	// MaxAge sets the time, in seconds, that the browser should remember that a site is only to be accessed using HTTPS.
	// A value of 0 disables HSTS.
	// Optional. Default: 0.
	MaxAge int

	// ExcludeSubdomains specifies whether the HSTS policy applies to all subdomains.
	// When set to true, the includeSubDomains directive is omitted.
	// Optional. Default: false.
	ExcludeSubdomains bool

	// PreloadEnabled adds the preload directive to the header, indicating consent to have the domain preloaded in browsers.
	// Note: You still need to submit your domain to hstspreload.org to be included in the preload list.
	// Optional. Default: false
	PreloadEnabled bool
}

// Config defines the config for Secure middleware.
type Config struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper

	// ContentSecurityPolicy sets the `Content-Security-Policy` header
	// which helps prevent XSS attacks by specifying which dynamic resources are allowed to load.
	// Reference: https://content-security-policy.com/
	// Optional. Default: "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self';".
	ContentSecurityPolicy string

	// ContentSecurityPolicyReportOnly sets the policy in report-only mode, which sends violation reports
	// but doesn't enforce the policy. Useful for testing before deployment.
	// Optional. Default: false.
	ContentSecurityPolicyReportOnly bool

	// CrossOriginEmbedderPolicy sets the `Cross-Origin-Embedder-Policy` header
	// which controls whether the document can embed resources from other origins.
	// Optional. Default: "require-corp".
	CrossOriginEmbedderPolicy string

	// CrossOriginOpenerPolicy sets the `Cross-Origin-Opener-Policy` header
	// which controls how the document interacts with cross-origin windows.
	// Optional. Default: "same-origin".
	CrossOriginOpenerPolicy string

	// CrossOriginResourcePolicy sets the `Cross-Origin-Resource-Policy` header
	// which restricts how a resource can be embedded in other websites.
	// Optional. Default: "same-origin".
	CrossOriginResourcePolicy string

	// PermissionsPolicy set the `Permissions-Policy` header
	// which controls which browser features can be used by the document and any embedded iframes.
	// Policy generator: https://www.permissionspolicy.com
	// Optional. Default: `permissionPolicyFeatures`.
	PermissionsPolicy string

	// ReferrerPolicy sets the `Referrer-Policy` header
	// which controls how much referrer information is included with requests.
	// Optional. Default: "no-referrer".
	ReferrerPolicy string

	// Server sets the `Server` header
	// Optional. Default: "".
	Server string

	// StrictTransportSecurity configures the HTTP Strict Transport Security header
	// which instructs browsers to only use HTTPS for the domain.
	StrictTransportSecurity StrictTransportSecurity

	// XContentTypeOptions sets the `X-Content-Type-Options` header
	// which prevents browsers from MIME-sniffing a response away from the declared content-type.
	// Optional. Default: "nosniff".
	XContentTypeOptions string

	// XFrameOptions sets the `X-Frame-Options` header
	// which indicates whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>.
	// Optional. Default: "DENY".
	// Possible values:
	// - "SAMEORIGIN" - Allow framing on same origin
	// - "DENY" - Deny framing completely
	XFrameOptions string
}
```
