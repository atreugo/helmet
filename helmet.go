package helmet

import (
	"strconv"

	"github.com/savsgio/atreugo/v11"
	gstrconv "github.com/savsgio/gotils/strconv"
)

// New returns a helmet middleware.
func New(cfg Config) atreugo.Middleware {
	if cfg.XSSProtection == "" {
		cfg.XSSProtection = defaultXSSProtection
	}

	if cfg.ContentTypeOptions == "" {
		cfg.ContentTypeOptions = defaultContentTypeOptions
	}

	if cfg.XFrameOptions == "" {
		cfg.XFrameOptions = defaultXFrameOptions
	}

	return func(ctx *atreugo.RequestCtx) error {
		if cfg.Filter != nil && cfg.Filter(ctx) {
			return ctx.Next()
		}

		ctx.Response.Header.Set(HeaderXXSSProtection, cfg.XSSProtection)
		ctx.Response.Header.Set(HeaderXContentTypeOptions, cfg.ContentTypeOptions)
		ctx.Response.Header.Set(HeaderXFrameOptions, cfg.XFrameOptions)

		isSecure := ctx.IsTLS() || (gstrconv.B2S(ctx.Request.Header.Peek(HeaderXForwardedProto)) == https)

		if isSecure && cfg.HSTSMaxAge != 0 {
			hstsMaxAgeSeconds := int64(cfg.HSTSMaxAge.Seconds())
			headerStrictTransportSecurityValue := "max-age=" + strconv.FormatInt(hstsMaxAgeSeconds, 10)

			if cfg.HSTSIncludeSubdomains {
				headerStrictTransportSecurityValue += "; includeSubdomains"
			}

			if cfg.HSTSPreloadEnabled {
				headerStrictTransportSecurityValue += "; preload"
			}

			ctx.Response.Header.Set(HeaderStrictTransportSecurity, headerStrictTransportSecurityValue)
		}

		if cfg.ContentSecurityPolicy != "" {
			if cfg.CSPReportOnly {
				ctx.Response.Header.Set(HeaderContentSecurityPolicyReportOnly, cfg.ContentSecurityPolicy)
			} else {
				ctx.Response.Header.Set(HeaderContentSecurityPolicy, cfg.ContentSecurityPolicy)
			}
		}

		if cfg.ReferrerPolicy != "" {
			ctx.Response.Header.Set(HeaderReferrerPolicy, cfg.ReferrerPolicy)
		}

		return ctx.Next()
	}
}
