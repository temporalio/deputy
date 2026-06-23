package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	dephttputil "github.com/temporalio/deputy/internal/httputil"
)

// Proxy-specific timeouts that differ from the shared defaults.
const (
	upstreamExpectContinue = 1 * time.Second
	upstreamResponseHeader = 30 * time.Second
	upstreamMaxIdleConns   = 100
	upstreamFlushInterval  = 100 * time.Millisecond
)

// Shared transport and client for upstream connections.
// Using a single transport allows connection pooling across all handlers,
// improving performance when proxying to multiple upstreams.
var (
	sharedTransportOnce sync.Once
	sharedTransport     *http.Transport
	sharedClientOnce    sync.Once
	sharedClient        *http.Client
)

// getSharedTransport returns the singleton upstream transport.
// This enables connection reuse across all proxy handlers.
func getSharedTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		sharedTransport = newUpstreamTransport()
	})
	return sharedTransport
}

// newUpstreamHTTPClient returns an HTTP client intended for outbound upstream fetches.
// It uses a shared transport to enable connection pooling across handlers.
func newUpstreamHTTPClient() *http.Client {
	sharedClientOnce.Do(func() {
		sharedClient = &http.Client{
			Transport: getSharedTransport(),
		}
	})
	return sharedClient
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
	// Build the proxy with Rewrite directly rather than via
	// NewSingleHostReverseProxy, which would set the deprecated Director field.
	// r.SetURL reproduces the single-host director's scheme/host/path-join
	// behavior.
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// Preserve the inbound X-Forwarded-For chain when present, matching
			// the legacy Director behavior.
			if r.Out.Header != nil && len(r.In.Header["X-Forwarded-For"]) > 0 {
				r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
			}
			r.SetURL(upstream)
			r.SetXForwarded()
		},
		Transport:     transport,
		FlushInterval: upstreamFlushInterval,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			onUpstreamError(w, r, ecosystem, err)
		},
	}
}
