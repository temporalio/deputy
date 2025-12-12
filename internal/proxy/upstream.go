package proxy

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

const (
	upstreamReadHeaderTimeout = 10 * time.Second
	upstreamIdleTimeout       = 90 * time.Second
	upstreamDialTimeout       = 10 * time.Second
	upstreamKeepAlive         = 30 * time.Second
	upstreamTLSHandshake      = 10 * time.Second
	upstreamExpectContinue    = 1 * time.Second
	upstreamResponseHeader    = 30 * time.Second
)

// newUpstreamHTTPClient returns an HTTP client intended for outbound upstream fetches.
// It is configured with timeouts suitable for production proxying.
func newUpstreamHTTPClient() *http.Client {
	return &http.Client{
		Transport: newUpstreamTransport(),
	}
}

// newUpstreamTransport returns a transport with conservative production timeouts and keep-alives.
func newUpstreamTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   upstreamDialTimeout,
		KeepAlive: upstreamKeepAlive,
	}

	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       upstreamIdleTimeout,
		TLSHandshakeTimeout:   upstreamTLSHandshake,
		ExpectContinueTimeout: upstreamExpectContinue,
		ResponseHeaderTimeout: upstreamResponseHeader,
		DisableCompression:    true,
	}
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
	proxy.FlushInterval = 100 * time.Millisecond
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		onUpstreamError(w, r, ecosystem, err)
	}

	return proxy
}
