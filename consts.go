package helmet

const https = "https"

const (
	defaultXSSProtection      = "1; mode=block"
	defaultContentTypeOptions = "nosniff"
	defaultXFrameOptions      = "SAMEORIGIN"
)

const (
	// HeaderXXSSProtection HTTP header.
	HeaderXXSSProtection = "X-XSS-Protection"

	// HeaderXContentTypeOptions HTTP header.
	HeaderXContentTypeOptions = "X-Content-Type-Options"

	// HeaderXFrameOptions HTTP header.
	HeaderXFrameOptions = "X-Frame-Options"

	// HeaderXForwardedProto HTTP header.
	HeaderXForwardedProto = "X-Forwarded-Proto"

	// HeaderStrictTransportSecurity HTTP header.
	HeaderStrictTransportSecurity = "Strict-Transport-Security"

	// HeaderContentSecurityPolicyReportOnly HTTP header.
	HeaderContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only"

	// HeaderContentSecurityPolicy HTTP header.
	HeaderContentSecurityPolicy = "Content-Security-Policy"

	// HeaderReferrerPolicy HTTP header.
	HeaderReferrerPolicy = "Referrer-Policy"
)
