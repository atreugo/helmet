package helmet

import (
	"strconv"
	"testing"
	"time"

	"github.com/savsgio/atreugo/v11"
	"github.com/valyala/fasthttp"
)

func testConfiguredMiddleware(t *testing.T, cfg Config) {
	t.Helper()

	hstsMaxAgeSeconds := int64(cfg.HSTSMaxAge.Seconds())
	headerStrictTransportSecurityValue := "max-age=" + strconv.FormatInt(hstsMaxAgeSeconds, 10)
	headerStrictTransportSecurityValue += "; includeSubdomains"
	headerStrictTransportSecurityValue += "; preload"

	ctx := atreugo.AcquireRequestCtx(new(fasthttp.RequestCtx))
	defer atreugo.ReleaseRequestCtx(ctx)

	ctx.Request.Header.Set(HeaderXForwardedProto, https)

	hm := New(cfg)

	if err := hm(ctx); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	headerContentSecurityPolicyReportOnlyValue := cfg.ContentSecurityPolicy
	headerContentSecurityPolicyValue := cfg.ContentSecurityPolicy

	if cfg.CSPReportOnly {
		headerContentSecurityPolicyValue = ""
	} else {
		headerContentSecurityPolicyReportOnlyValue = ""
	}

	expectedHeaders := []struct {
		header string
		value  string
	}{
		{header: HeaderXXSSProtection, value: defaultXSSProtection},
		{header: HeaderXContentTypeOptions, value: defaultContentTypeOptions},
		{header: HeaderXFrameOptions, value: defaultXFrameOptions},
		{header: HeaderStrictTransportSecurity, value: headerStrictTransportSecurityValue},
		{header: HeaderContentSecurityPolicyReportOnly, value: headerContentSecurityPolicyReportOnlyValue},
		{header: HeaderContentSecurityPolicy, value: headerContentSecurityPolicyValue},
		{header: HeaderReferrerPolicy, value: cfg.ReferrerPolicy},
	}

	for _, headerValue := range expectedHeaders {
		value := string(ctx.Response.Header.Peek(headerValue.header))
		expectedValue := headerValue.value

		if cfg.Filter != nil && cfg.Filter(ctx) {
			expectedValue = ""
		}

		if value != expectedValue {
			t.Errorf("Response header %s == %s, want %s", headerValue.header, value, headerValue.value)
		}
	}
}

func Test_New(t *testing.T) {
	if hm := New(Config{}); hm == nil {
		t.Error("New() returns nil")
	}
}

func Test_middleware(t *testing.T) {
	cfg := Config{
		HSTSMaxAge:            10 * time.Second,
		HSTSIncludeSubdomains: true,
		HSTSPreloadEnabled:    true,
		ContentSecurityPolicy: "default-src https: 'unsafe-eval' 'unsafe-inline'; object-src 'none'",
		CSPReportOnly:         false,
		ReferrerPolicy:        "origin",
	}

	testConfiguredMiddleware(t, cfg)

	cfg.CSPReportOnly = true

	testConfiguredMiddleware(t, cfg)

	cfg.Filter = func(ctx *atreugo.RequestCtx) bool { return true }

	testConfiguredMiddleware(t, cfg)
}
