package secure

import (
	"fmt"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const (
	HeaderCrossOriginEmbedderPolicy = "Cross-Origin-Embedder-Policy"
	HeaderCrossOriginOpenerPolicy   = "Cross-Origin-Opener-Policy"
	HeaderCrossOriginResourcePolicy = "Cross-Origin-Resource-Policy"
	HeaderPermissionsPolicy         = "Permissions-Policy"
)

var permissionPolicyFeatures = []string{
	"accelerometer=()",
	"autoplay=()",
	"camera=()",
	"cross-origin-isolated=()",
	"display-capture=()",
	"encrypted-media=()",
	"fullscreen=()",
	"geolocation=()",
	"gyroscope=()",
	"keyboard-map=()",
	"magnetometer=()",
	"microphone=()",
	"midi=()",
	"payment=()",
	"picture-in-picture=()",
	"publickey-credentials-get=()",
	"screen-wake-lock=()",
	"sync-xhr=()",
	"usb=()",
	"web-share=()",
	"xr-spatial-tracking=()",
}

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

// DefaultSecureConfig is the default Secure middleware config.
// It provides a secure baseline for web applications but may need customization for specific requirements.
var DefaultSecureConfig = Config{
	Skipper:                   middleware.DefaultSkipper,
	ContentSecurityPolicy:     "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self';",
	CrossOriginEmbedderPolicy: "require-corp",
	CrossOriginOpenerPolicy:   "same-origin",
	CrossOriginResourcePolicy: "same-origin",
	PermissionsPolicy:         strings.Join(permissionPolicyFeatures, ", "),
	ReferrerPolicy:            "no-referrer",
	StrictTransportSecurity: StrictTransportSecurity{
		MaxAge:            0,
		ExcludeSubdomains: false,
		PreloadEnabled:    false,
	},
	XContentTypeOptions: "nosniff",
	XFrameOptions:       "DENY",
}

// New returns a middleware with optional custom configuration.
// This middleware adds various security-related HTTP headers to each response.
// If no configuration is provided, it uses DefaultSecureConfig.
func New(config ...Config) echo.MiddlewareFunc {
	cfg := DefaultSecureConfig
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.Skipper == nil {
		cfg.Skipper = DefaultSecureConfig.Skipper
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if cfg.Skipper(c) {
				return next(c)
			}

			req := c.Request()
			res := c.Response()

			if cfg.ContentSecurityPolicy != "" {
				if cfg.ContentSecurityPolicyReportOnly {
					res.Header().Set(echo.HeaderContentSecurityPolicyReportOnly, cfg.ContentSecurityPolicy)
				} else {
					res.Header().Set(echo.HeaderContentSecurityPolicy, cfg.ContentSecurityPolicy)
				}
			}

			if cfg.CrossOriginEmbedderPolicy != "" {
				res.Header().Set(HeaderCrossOriginEmbedderPolicy, cfg.CrossOriginEmbedderPolicy)
			}

			if cfg.CrossOriginOpenerPolicy != "" {
				res.Header().Set(HeaderCrossOriginOpenerPolicy, cfg.CrossOriginOpenerPolicy)
			}

			if cfg.CrossOriginResourcePolicy != "" {
				res.Header().Set(HeaderCrossOriginResourcePolicy, cfg.CrossOriginResourcePolicy)
			}

			if cfg.PermissionsPolicy != "" {
				res.Header().Set(HeaderPermissionsPolicy, cfg.PermissionsPolicy)
			}

			if cfg.ReferrerPolicy != "" {
				res.Header().Set(echo.HeaderReferrerPolicy, cfg.ReferrerPolicy)
			}

			if cfg.Server != "" {
				res.Header().Set(echo.HeaderServer, cfg.Server)
			}

			if (c.IsTLS() || (req.Header.Get(echo.HeaderXForwardedProto) == "https")) && cfg.StrictTransportSecurity.MaxAge != 0 {
				subdomains := ""
				if !cfg.StrictTransportSecurity.ExcludeSubdomains {
					subdomains = "; includeSubdomains"
				}
				if cfg.StrictTransportSecurity.PreloadEnabled {
					subdomains = fmt.Sprintf("%s; preload", subdomains)
				}
				res.Header().Set(echo.HeaderStrictTransportSecurity, fmt.Sprintf("max-age=%d%s", cfg.StrictTransportSecurity.MaxAge, subdomains))
			}

			if cfg.XContentTypeOptions != "" {
				res.Header().Set(echo.HeaderXContentTypeOptions, cfg.XContentTypeOptions)
			}

			if cfg.XFrameOptions != "" {
				res.Header().Set(echo.HeaderXFrameOptions, cfg.XFrameOptions)
			}

			return next(c)
		}
	}
}
