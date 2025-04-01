package secure

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestNewWithConfig(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	testCases := []struct {
		name     string
		config   Config
		tls      bool
		expected map[string]string
	}{
		{
			name:   "Default config",
			config: DefaultConfig,
			expected: map[string]string{
				echo.HeaderContentSecurityPolicy: "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self';",
				HeaderCrossOriginEmbedderPolicy:  "require-corp",
				HeaderCrossOriginOpenerPolicy:    "same-origin",
				HeaderCrossOriginResourcePolicy:  "same-origin",
				HeaderPermissionsPolicy:          strings.Join(permissionPolicyFeatures, ", "),
				echo.HeaderReferrerPolicy:        "no-referrer",
				echo.HeaderXContentTypeOptions:   "nosniff",
				echo.HeaderXFrameOptions:         "DENY",
			},
		},
		{
			name: "Custom CSP",
			config: Config{
				ContentSecurityPolicy: "default-src 'self'",
			},
			expected: map[string]string{
				echo.HeaderContentSecurityPolicy: "default-src 'self'",
			},
		},
		{
			name: "CSP Report Only",
			config: Config{
				ContentSecurityPolicy:           "default-src 'self'",
				ContentSecurityPolicyReportOnly: true,
			},
			expected: map[string]string{
				echo.HeaderContentSecurityPolicyReportOnly: "default-src 'self'",
			},
		},
		{
			name: "HSTS enabled with TLS",
			config: Config{
				StrictTransportSecurity: StrictTransportSecurity{
					MaxAge: 31536000,
				},
			},
			tls: true,
			expected: map[string]string{
				echo.HeaderStrictTransportSecurity: "max-age=31536000; includeSubdomains",
			},
		},
		{
			name: "HSTS with all options",
			config: Config{
				StrictTransportSecurity: StrictTransportSecurity{
					MaxAge:            63072000,
					ExcludeSubdomains: true,
					PreloadEnabled:    true,
				},
			},
			tls: true,
			expected: map[string]string{
				echo.HeaderStrictTransportSecurity: "max-age=63072000; preload",
			},
		},
		{
			name: "Custom Permissions Policy",
			config: Config{
				PermissionsPolicy: "camera=(), microphone=()",
			},
			expected: map[string]string{
				HeaderPermissionsPolicy: "camera=(), microphone=()",
			},
		},
		{
			name: "Custom Referrer Policy",
			config: Config{
				ReferrerPolicy: "strict-origin-when-cross-origin",
			},
			expected: map[string]string{
				echo.HeaderReferrerPolicy: "strict-origin-when-cross-origin",
			},
		},
		{
			name: "Custom Server header",
			config: Config{
				Server: "MyCustomServer",
			},
			expected: map[string]string{
				echo.HeaderServer: "MyCustomServer",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if tc.tls {
				c.SetRequest(httptest.NewRequest(http.MethodGet, "/", nil).WithContext(
					req.Context(),
				))
				c.Request().TLS = &tls.ConnectionState{}
			} else if req.Header.Get(echo.HeaderXForwardedProto) == "https" {
				c.Request().Header.Set(echo.HeaderXForwardedProto, "https")
			}

			middleware := New(tc.config)
			err := middleware(h)(c)

			assert.NoError(t, err)

			for header, value := range tc.expected {
				assert.Equal(t, value, rec.Header().Get(header), "Header %s not set correctly", header)
			}
		})
	}
}

func TestSkipper(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	middleware := New(Config{
		Skipper: func(c echo.Context) bool {
			return true
		},
		ContentSecurityPolicy: "default-src 'self'",
	})

	err := middleware(h)(c)

	assert.NoError(t, err)

	assert.Empty(t, rec.Header().Get(echo.HeaderContentSecurityPolicy))
}

func TestNew(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	middleware := New()
	err := middleware(h)(c)

	assert.NoError(t, err)

	assert.Equal(t, DefaultConfig.ContentSecurityPolicy, rec.Header().Get(echo.HeaderContentSecurityPolicy))
	assert.Equal(t, DefaultConfig.CrossOriginEmbedderPolicy, rec.Header().Get(HeaderCrossOriginEmbedderPolicy))
	assert.Equal(t, DefaultConfig.CrossOriginOpenerPolicy, rec.Header().Get(HeaderCrossOriginOpenerPolicy))
	assert.Equal(t, DefaultConfig.CrossOriginResourcePolicy, rec.Header().Get(HeaderCrossOriginResourcePolicy))
	assert.Equal(t, DefaultConfig.PermissionsPolicy, rec.Header().Get(HeaderPermissionsPolicy))
	assert.Equal(t, DefaultConfig.ReferrerPolicy, rec.Header().Get(echo.HeaderReferrerPolicy))
	assert.Equal(t, DefaultConfig.XContentTypeOptions, rec.Header().Get(echo.HeaderXContentTypeOptions))
	assert.Equal(t, DefaultConfig.XFrameOptions, rec.Header().Get(echo.HeaderXFrameOptions))
}
