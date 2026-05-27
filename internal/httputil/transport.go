// Package httputil provides shared HTTP client creation and configuration.
// It integrates with the config system for centralized HTTP settings while
// providing sensible defaults for standalone usage.
package httputil

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/temporalio/deputy/internal/network"
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

// NewSafeTransport returns an http.Transport with SSRF protection using network.SafeDialer.
// It blocks connections to private networks, loopback addresses, link-local addresses,
// and common cloud metadata endpoints. Use this for any HTTP requests to user-controlled URLs.
//
// The transport uses the same production-friendly defaults as NewTransport.
func NewSafeTransport() *http.Transport {
	dialer := network.NewSafeDialerWithOptions(
		network.WithDialer(&net.Dialer{
			Timeout:   DefaultDialTimeout,
			KeepAlive: DefaultKeepAlive,
		}),
	)
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
	}
}

// NewSafeTransportWithOptions returns an http.Transport with SSRF protection and custom SafeDialer options.
// Use this when you need to customize the SafeDialer behavior (e.g., allow private networks).
//
// Example:
//
//	transport := NewSafeTransportWithOptions(network.WithAllowPrivate())
func NewSafeTransportWithOptions(opts ...network.Option) *http.Transport {
	dialer := network.NewSafeDialerWithOptions(
		network.WithDialer(&net.Dialer{
			Timeout:   DefaultDialTimeout,
			KeepAlive: DefaultKeepAlive,
		}),
	)
	for _, opt := range opts {
		opt(dialer)
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
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

// NewSafeClient returns an http.Client with SSRF protection using network.SafeDialer.
// It blocks connections to private networks, loopback addresses, link-local addresses,
// and common cloud metadata endpoints. Use this for any HTTP requests to user-controlled URLs.
func NewSafeClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: NewSafeTransport(),
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

// NewSafeRetryableClient returns an http.Client with automatic retry support and SSRF protection.
// It combines exponential backoff for transient failures with SafeDialer to block connections
// to private networks, loopback addresses, link-local addresses, and cloud metadata endpoints.
//
// Use this for external API calls to user-controlled URLs that need retry support.
func NewSafeRetryableClient(timeout time.Duration) *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = nil
	rc.HTTPClient = &http.Client{
		Timeout:   timeout,
		Transport: NewSafeTransport(),
	}
	rc.RetryMax = DefaultRetryMax
	rc.RetryWaitMin = DefaultRetryWaitMin
	rc.RetryWaitMax = DefaultRetryWaitMax
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

// NewSafeInstrumentedClient returns an http.Client with both SSRF protection and OTel tracing.
// Combines SafeDialer protection with distributed tracing for user-controlled URLs.
func NewSafeInstrumentedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: InstrumentedTransport(NewSafeTransport()),
	}
}

// NewSafeInstrumentedRetryableClient returns a retryable http.Client with SSRF protection and OTel tracing.
// Combines SafeDialer protection, automatic retry support, and distributed tracing.
// Use this for external API calls to user-controlled URLs that need both retry and observability.
func NewSafeInstrumentedRetryableClient(timeout time.Duration) *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = nil
	rc.HTTPClient = &http.Client{
		Timeout:   timeout,
		Transport: InstrumentedTransport(NewSafeTransport()),
	}
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

// ClientConfig contains all settings needed to create an HTTP client.
// This mirrors config.HTTPConfig but avoids a circular dependency.
type ClientConfig struct {
	// Connection timeouts
	Timeout               time.Duration
	DialTimeout           time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	KeepAlive             time.Duration
	IdleConnTimeout       time.Duration

	// Connection pool settings
	MaxIdleConns        int
	MaxIdleConnsPerHost int

	// Retry settings
	RetryEnabled bool
	RetryMax     int
	RetryWaitMin time.Duration
	RetryWaitMax time.Duration

	// Instrumentation
	EnableOTel bool

	// Security
	// EnableSSRFProtection enables SafeDialer to block connections to private networks,
	// loopback addresses, link-local addresses, and cloud metadata endpoints.
	// Use this for clients that make requests to user-controlled URLs.
	EnableSSRFProtection bool

	// SafeDialerOptions allows customizing SafeDialer behavior when EnableSSRFProtection is true.
	// For example, use network.WithAllowPrivate() to allow internal network access.
	SafeDialerOptions []network.Option
}

// DefaultClientConfig returns a ClientConfig with production-ready defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Timeout:               30 * time.Second,
		DialTimeout:           DefaultDialTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
		KeepAlive:             DefaultKeepAlive,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		RetryEnabled:          true,
		RetryMax:              DefaultRetryMax,
		RetryWaitMin:          DefaultRetryWaitMin,
		RetryWaitMax:          DefaultRetryWaitMax,
		EnableOTel:            false,
	}
}

// NewTransportFromConfig creates an http.Transport from the provided configuration.
// If EnableSSRFProtection is true, the transport uses SafeDialer for SSRF protection.
func NewTransportFromConfig(cfg ClientConfig) *http.Transport {
	var dialContext func(ctx context.Context, network, address string) (net.Conn, error)

	if cfg.EnableSSRFProtection {
		// Use SafeDialer with custom options
		opts := append([]network.Option{
			network.WithDialer(&net.Dialer{
				Timeout:   cfg.DialTimeout,
				KeepAlive: cfg.KeepAlive,
			}),
		}, cfg.SafeDialerOptions...)
		dialer := network.NewSafeDialerWithOptions(opts...)
		dialContext = dialer.DialContext
	} else {
		dialContext = (&net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: cfg.KeepAlive,
		}).DialContext
	}

	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
	}
}

// NewSafeTransportFromConfig creates an http.Transport with SSRF protection from the provided configuration.
// This is a convenience function equivalent to setting EnableSSRFProtection=true in the config.
func NewSafeTransportFromConfig(cfg ClientConfig) *http.Transport {
	cfg.EnableSSRFProtection = true
	return NewTransportFromConfig(cfg)
}

// NewClientFromConfig creates an http.Client configured from ClientConfig.
// If retry is enabled and RetryMax > 0, the client will automatically retry
// transient failures with exponential backoff.
func NewClientFromConfig(cfg ClientConfig) *http.Client {
	if cfg.RetryEnabled && cfg.RetryMax > 0 {
		return newRetryableClientFromConfig(cfg)
	}
	return newSimpleClientFromConfig(cfg)
}

func newSimpleClientFromConfig(cfg ClientConfig) *http.Client {
	transport := NewTransportFromConfig(cfg)
	var rt http.RoundTripper = transport
	if cfg.EnableOTel {
		rt = InstrumentedTransport(transport)
	}
	return &http.Client{
		Timeout:   cfg.Timeout,
		Transport: rt,
	}
}

func newRetryableClientFromConfig(cfg ClientConfig) *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = nil // disable noisy retry logging

	// Use cleanhttp for pooled connections with custom settings
	pooledClient := cleanhttp.DefaultPooledClient()
	pooledClient.Timeout = cfg.Timeout

	// Apply transport configuration
	if t, ok := pooledClient.Transport.(*http.Transport); ok {
		if cfg.EnableSSRFProtection {
			// Use SafeDialer with custom options
			opts := append([]network.Option{
				network.WithDialer(&net.Dialer{
					Timeout:   cfg.DialTimeout,
					KeepAlive: cfg.KeepAlive,
				}),
			}, cfg.SafeDialerOptions...)
			dialer := network.NewSafeDialerWithOptions(opts...)
			t.DialContext = dialer.DialContext
		} else {
			t.DialContext = (&net.Dialer{
				Timeout:   cfg.DialTimeout,
				KeepAlive: cfg.KeepAlive,
			}).DialContext
		}
		t.MaxIdleConns = cfg.MaxIdleConns
		t.MaxIdleConnsPerHost = cfg.MaxIdleConnsPerHost
		t.IdleConnTimeout = cfg.IdleConnTimeout
		t.TLSHandshakeTimeout = cfg.TLSHandshakeTimeout
		t.ResponseHeaderTimeout = cfg.ResponseHeaderTimeout
	}

	if cfg.EnableOTel {
		pooledClient.Transport = InstrumentedTransport(pooledClient.Transport)
	}

	rc.HTTPClient = pooledClient
	rc.RetryMax = cfg.RetryMax
	rc.RetryWaitMin = cfg.RetryWaitMin
	rc.RetryWaitMax = cfg.RetryWaitMax

	client := rc.StandardClient()
	client.Timeout = cfg.Timeout
	return client
}
