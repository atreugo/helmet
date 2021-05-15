package helmet

import (
	"time"

	"github.com/savsgio/atreugo/v11"
)

// Config is the configuration of the helmet middleware.
type Config struct { // nolint:maligned
	// The time that the browser should remember that a site is only to be accessed using HTTPS (optional).
	HSTSMaxAge time.Duration

	// If enabled, this rule applies to all of the site's subdomains as well (optional).
	HSTSIncludeSubdomains bool

	// nolint:lll
	// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security#preloading_strict_transport_security
	HSTSPreloadEnabled bool

	// The X-XSS-Protection response header stops pages from loading
	// when they detect reflected cross-site scripting (XSS) attacks.
	// Although these protections are largely unnecessary in modern browsers
	// when sites implement a strong Content-Security-Policy that disables
	// the use of inline JavaScript ('unsafe-inline'),
	// they can still provide protections for users of older web browsers that don't yet support CSP.
	//
	// Default: "1; mode=block".
	XSSProtection string

	// The X-Content-Type-Options response header is a marker used by the server to indicate
	// that the MIME types advertised in the Content-Type headers should not be changed and be followed.
	// This is a way to opt out of MIME type sniffing, or, in other words,
	// to say that the MIME types are deliberately configured.
	//
	// Default: "nosniff".
	ContentTypeOptions string

	// The X-Frame-Options response header can be used to indicate whether or not a browser
	// should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>.
	// Sites can use this to avoid click-jacking attacks,
	// by ensuring that their content is not embedded into other sites.
	//
	// Default: "SAMEORIGIN".
	XFrameOptions string

	// The Content-Security-Policy response header allows web site administrators to control resources
	// the user agent is allowed to load for a given page.
	// With a few exceptions, policies mostly involve specifying server origins and script endpoints.
	// This helps guard against cross-site scripting attacks (XSS). (optional).
	ContentSecurityPolicy string

	// The Content-Security-Policy-Report-Only response header allows web developers to experiment
	// with policies by monitoring (but not enforcing) their effects.
	// These violation reports consist of JSON documents sent via an HTTP POST request to the specified URI.
	// (optional).
	CSPReportOnly bool

	// The Referrer-Policy response header controls how much referrer information (sent via the Referer header)
	// should be included with requests. Aside from the HTTP header, you can set this policy in HTML.
	// (optional).
	ReferrerPolicy string

	// Filter defines a rule to skip this middleware (optional).
	Filter func(*atreugo.RequestCtx) bool
}
