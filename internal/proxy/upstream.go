package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	dephttputil "github.com/picatz/deputy/internal/httputil"
)

// Proxy-specific timeouts that differ from the shared defaults.
const (
	upstreamExpectContinue = 1 * time.Second
	upstreamResponseHeader = 30 * time.Second
	upstreamMaxIdleConns   = 100
	upstreamFlushInterval  = 100 * time.Millisecond
)

// newUpstreamHTTPClient returns an HTTP client intended for outbound upstream fetches.
// It is configured with timeouts suitable for production proxying.
func newUpstreamHTTPClient() *http.Client {
	return &http.Client{
		Transport: newUpstreamTransport(),
	}
}

// newUpstreamTransport returns a transport with conservative production timeouts and keep-alives.
// It builds on the shared defaults but overrides settings specific to proxying.
func newUpstreamTransport() *http.Transport {
	t := dephttputil.NewTransport()
	t.MaxIdleConns = upstreamMaxIdleConns
	t.ExpectContinueTimeout = upstreamExpectContinue
	t.ResponseHeaderTimeout = upstreamResponseHeader
	t.DisableCompression = true
	return t
}

// newUpstreamReverseProxy creates a reverse proxy that forwards requests to upstream.
// It enforces correct Host header forwarding and uses the shared upstream error mapping.
func newUpstreamReverseProxy(upstream *url.URL, ecosystem string, transport http.RoundTripper) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Director = nil
	proxy.Rewrite = func(r *httputil.ProxyRequest) {
		// Preserve the inbound X-Forwarded-For chain when present, matching the
		// legacy Director behavior.
		if r.Out.Header != nil && len(r.In.Header["X-Forwarded-For"]) > 0 {
			r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
		}
		r.SetURL(upstream)
		r.SetXForwarded()
	}

	proxy.Transport = transport
	proxy.FlushInterval = upstreamFlushInterval
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		onUpstreamError(w, r, ecosystem, err)
	}

	return proxy
}
