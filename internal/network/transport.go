package network

import (
	"net"
	"net/http"
	"net/netip"
	"time"
)

// SafeTransport returns an http.RoundTripper that uses SafeDialer for SSRF protection.
// It prevents connections to private networks, loopback, and cloud metadata endpoints.
func SafeTransport() http.RoundTripper {
	dialer := NewSafeDialer()
	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// SafeClient returns an http.Client that uses SafeDialer for SSRF protection.
// Use this client for any HTTP requests to user-controlled URLs on remote servers.
func SafeClient() *http.Client {
	return &http.Client{
		Transport: SafeTransport(),
		Timeout:   30 * time.Second,
	}
}

// SafeTransportWithOptions returns an http.RoundTripper with custom SafeDialer options.
func SafeTransportWithOptions(opts ...Option) http.RoundTripper {
	dialer := NewSafeDialerWithOptions(opts...)
	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// WithAllowPrivate allows connections to private network ranges.
func WithAllowPrivate() Option {
	return func(d *SafeDialer) {
		d.AllowPrivate = true
	}
}

// WithAllowedHosts allows explicit host allowlisting.
func WithAllowedHosts(hosts ...string) Option {
	return func(d *SafeDialer) {
		d.AllowedHosts = append(d.AllowedHosts, hosts...)
	}
}

// WithAllowedCIDRs allows explicit CIDR allowlisting.
func WithAllowedCIDRs(prefixes ...netip.Prefix) Option {
	return func(d *SafeDialer) {
		d.AllowedCIDRs = append(d.AllowedCIDRs, prefixes...)
	}
}

// WithAllowLoopback allows connections to loopback addresses.
func WithAllowLoopback() Option {
	return func(d *SafeDialer) {
		d.AllowLoopback = true
	}
}

// WithAllowLinkLocal allows connections to link-local addresses.
func WithAllowLinkLocal() Option {
	return func(d *SafeDialer) {
		d.AllowLinkLocal = true
	}
}

// WithBlockedHosts sets additional blocked hostnames.
func WithBlockedHosts(hosts ...string) Option {
	return func(d *SafeDialer) {
		d.BlockedHosts = append(d.BlockedHosts, hosts...)
	}
}

// WithDialer sets a custom underlying net.Dialer.
func WithDialer(dialer *net.Dialer) Option {
	return func(d *SafeDialer) {
		d.Dialer = dialer
	}
}

// WithResolver sets a custom DNS resolver.
func WithResolver(resolver *net.Resolver) Option {
	return func(d *SafeDialer) {
		d.Resolver = resolver
	}
}
