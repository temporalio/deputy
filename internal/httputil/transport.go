// Package httputil provides shared HTTP configuration constants and helpers.
package httputil

import (
	"net"
	"net/http"
	"time"
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
