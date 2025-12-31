// Package httputil provides shared HTTP configuration constants and helpers.
package httputil

import (
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Common HTTP client timeout constants used across deputy subsystems.
// These values represent best practices for production HTTP clients.
const (
	// DefaultDialTimeout is the maximum time to establish a TCP connection.
	DefaultDialTimeout = 10 * time.Second

	// DefaultKeepAlive is the interval between TCP keep-alive probes.
	DefaultKeepAlive = 30 * time.Second

	// DefaultIdleConnTimeout is how long idle connections remain in the pool.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultTLSHandshakeTimeout is the maximum time for TLS handshake.
	DefaultTLSHandshakeTimeout = 10 * time.Second

	// DefaultResponseHeaderTimeout is the maximum time to wait for response headers.
	DefaultResponseHeaderTimeout = 20 * time.Second

	// DefaultMaxIdleConns is the maximum number of idle connections in the pool.
	DefaultMaxIdleConns = 20

	// DefaultMaxIdleConnsPerHost is the maximum number of idle connections per host.
	// The default http.Transport value is 2, which limits connection reuse when
	// talking to a single upstream. We set this higher to improve throughput.
	DefaultMaxIdleConnsPerHost = 10
)

// NewTransport returns an http.Transport configured with production-friendly defaults.
// The transport uses sensible timeouts for dialing, TLS, and connection pooling.
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   DefaultDialTimeout,
			KeepAlive: DefaultKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
	}
}

// NewClient returns an http.Client with the given timeout and a production transport.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: NewTransport(),
	}
}

// Retry configuration defaults for retryable HTTP clients.
const (
	// DefaultRetryMax is the maximum number of retries for transient failures.
	DefaultRetryMax = 3

	// DefaultRetryWaitMin is the minimum wait time between retries.
	DefaultRetryWaitMin = 500 * time.Millisecond

	// DefaultRetryWaitMax is the maximum wait time between retries.
	DefaultRetryWaitMax = 5 * time.Second
)

// NewRetryableClient returns an http.Client with automatic retry support for
// transient failures (5xx errors, connection errors, etc.). This is ideal for
// external API calls to services like GitHub, OSV, or package registries.
//
// The client uses exponential backoff with jitter and respects Retry-After headers.
// Logging is disabled by default to avoid noisy output.
func NewRetryableClient(timeout time.Duration) *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = nil // disable noisy retry logging
	rc.HTTPClient = cleanhttp.DefaultPooledClient()
	rc.HTTPClient.Timeout = timeout
	rc.RetryMax = DefaultRetryMax
	rc.RetryWaitMin = DefaultRetryWaitMin
	rc.RetryWaitMax = DefaultRetryWaitMax
	// StandardClient() returns a wrapper that uses the retryable transport,
	// but we need to set the timeout on the returned client as well
	client := rc.StandardClient()
	client.Timeout = timeout
	return client
}

// NewRetryableClientWithConfig returns a retryable HTTP client with custom retry settings.
// Use this when you need different retry behavior than the defaults.
func NewRetryableClientWithConfig(timeout time.Duration, retryMax int, retryWaitMin, retryWaitMax time.Duration) *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = nil
	rc.HTTPClient = cleanhttp.DefaultPooledClient()
	rc.HTTPClient.Timeout = timeout
	rc.RetryMax = retryMax
	rc.RetryWaitMin = retryWaitMin
	rc.RetryWaitMax = retryWaitMax
	client := rc.StandardClient()
	client.Timeout = timeout
	return client
}

// InstrumentedTransport wraps an http.RoundTripper with OpenTelemetry tracing.
// Creates client spans for outgoing HTTP requests with proper context propagation.
// If base is nil, uses http.DefaultTransport.
func InstrumentedTransport(base http.RoundTripper, opts ...otelhttp.Option) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base, opts...)
}

// NewInstrumentedClient returns an http.Client with OTel tracing enabled.
// All outgoing requests will create spans and propagate trace context.
func NewInstrumentedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: InstrumentedTransport(NewTransport()),
	}
}

// NewInstrumentedRetryableClient returns a retryable http.Client with OTel tracing.
// Combines automatic retry support with distributed tracing.
func NewInstrumentedRetryableClient(timeout time.Duration) *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = nil
	rc.HTTPClient = cleanhttp.DefaultPooledClient()
	rc.HTTPClient.Timeout = timeout
	rc.HTTPClient.Transport = InstrumentedTransport(rc.HTTPClient.Transport)
	rc.RetryMax = DefaultRetryMax
	rc.RetryWaitMin = DefaultRetryWaitMin
	rc.RetryWaitMax = DefaultRetryWaitMax
	client := rc.StandardClient()
	client.Timeout = timeout
	return client
}

// InstrumentedHandler wraps an http.Handler with OpenTelemetry tracing.
// Creates server spans for incoming HTTP requests.
func InstrumentedHandler(handler http.Handler, operation string, opts ...otelhttp.Option) http.Handler {
	return otelhttp.NewHandler(handler, operation, opts...)
}

// InstrumentedMiddleware returns middleware that wraps handlers with OTel tracing.
func InstrumentedMiddleware(operation string, opts ...otelhttp.Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return InstrumentedHandler(next, operation, opts...)
	}
}
