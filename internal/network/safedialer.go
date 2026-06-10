// Package network provides secure networking primitives for Deputy.
//
// The SafeDialer prevents SSRF attacks by validating resolved IP addresses
// at connection time, after DNS resolution. This eliminates DNS rebinding
// vulnerabilities where an attacker could use a domain that resolves to
// internal IPs.
//
// # Composability
//
// SafeDialer implements the standard DialContext signature, making it
// composable with any Go networking code that accepts a dialer function:
//
//	// With http.Transport
//	transport := &http.Transport{
//	    DialContext: network.NewSafeDialer().DialContext,
//	}
//
//	// With grpc.Dial
//	conn, err := grpc.Dial(target,
//	    grpc.WithContextDialer(network.NewSafeDialer().DialContext),
//	)
//
//	// With database drivers
//	dialer := network.NewSafeDialer()
//	db.SetConnector(&customConnector{dial: dialer.DialContext})
//
//	// Wrapping an existing dialer
//	existingDialer := &net.Dialer{Timeout: 10 * time.Second}
//	safeDialer := &network.SafeDialer{Dialer: existingDialer}
//
// # Two-Layer Defense
//
// For complete SSRF protection, use both ValidateRemoteTarget (fast early
// rejection) and SafeDialer (connection-time validation):
//
//	// Layer 1: Early rejection with helpful error messages
//	if err := targets.ValidateRemoteTarget(userInput); err != nil {
//	    return err // User gets guidance on valid inputs
//	}
//
//	// Layer 2: Connection-time validation (catches DNS rebinding)
//	client := &http.Client{
//	    Transport: &http.Transport{
//	        DialContext: network.NewSafeDialer().DialContext,
//	    },
//	}
package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// DialContextFunc is the standard signature for context-aware dial functions.
// This matches net.Dialer.DialContext, http.Transport.DialContext, and
// grpc.WithContextDialer.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// SafeDialer wraps a dialer with IP validation to prevent SSRF attacks.
// It resolves hostnames and validates IP addresses before connecting,
// eliminating DNS rebinding vulnerabilities.
//
// SafeDialer is safe for concurrent use.
type SafeDialer struct {
	// Dialer is the underlying dialer. If nil, a default dialer is used.
	// You can set this to wrap an existing *net.Dialer with custom settings.
	Dialer *net.Dialer

	// AllowPrivate allows connections to private network ranges (10.x, 172.16-31.x, 192.168.x).
	// Default: false (block private networks)
	AllowPrivate bool

	// AllowLoopback allows connections to loopback addresses (127.x.x.x, ::1).
	// Default: false (block loopback)
	AllowLoopback bool

	// AllowLinkLocal allows connections to link-local addresses (169.254.x.x, fe80::).
	// This includes cloud metadata endpoints.
	// Default: false (block link-local)
	AllowLinkLocal bool

	// AllowedHosts is a list of hostnames allowed to resolve to private IPs.
	// Entries may be exact hosts or suffixes prefixed with a dot (e.g., ".corp.local").
	AllowedHosts []string

	// AllowedCIDRs is a list of CIDR ranges allowed for outbound connections.
	AllowedCIDRs []netip.Prefix

	// BlockedHosts is a list of hostnames to block (case-insensitive).
	// Common metadata hostnames are blocked by default.
	BlockedHosts []string

	// Resolver is used for DNS lookups. If nil, net.DefaultResolver is used.
	Resolver *net.Resolver
}

// DefaultBlockedHosts returns the default list of blocked hostnames.
func DefaultBlockedHosts() []string {
	return []string{
		"localhost",
		"metadata.google.internal",
		"metadata.goog",
		"metadata.azure.com",
		"management.azure.com",
		"instance-data",
		"metadata",
	}
}

// NewSafeDialer creates a SafeDialer with secure defaults.
// It blocks private networks, loopback, link-local, and common metadata hostnames.
//
// Use NewSafeDialerWithOptions to customize behavior:
//
//	dialer := network.NewSafeDialerWithOptions(
//	    network.WithAllowPrivate(),
//	    network.WithDialer(&net.Dialer{Timeout: 10 * time.Second}),
//	)
func NewSafeDialer() *SafeDialer {
	d := &SafeDialer{
		Dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		BlockedHosts: DefaultBlockedHosts(),
	}
	for _, opt := range defaultSafeDialerOptions() {
		opt(d)
	}
	return d
}

// NewSafeDialerWithOptions creates a SafeDialer with custom options.
//
//	// Allow connections to private networks (for internal services)
//	dialer := network.NewSafeDialerWithOptions(network.WithAllowPrivate())
//
//	// Use a custom timeout
//	dialer := network.NewSafeDialerWithOptions(
//	    network.WithDialer(&net.Dialer{Timeout: 5 * time.Second}),
//	)
func NewSafeDialerWithOptions(opts ...Option) *SafeDialer {
	d := NewSafeDialer()
	for _, opt := range opts {
		opt(d)
	}
	return d
}

var defaultSafeDialerOpts atomic.Value

func init() {
	defaultSafeDialerOpts.Store([]Option(nil))
}

// SetDefaultSafeDialerOptions sets default SafeDialer options applied to all new dialers.
// This is intended for process-wide configuration, such as server egress allowlists.
func SetDefaultSafeDialerOptions(opts ...Option) {
	copied := append([]Option(nil), opts...)
	defaultSafeDialerOpts.Store(copied)
}

func defaultSafeDialerOptions() []Option {
	if value := defaultSafeDialerOpts.Load(); value != nil {
		if opts, ok := value.([]Option); ok {
			return append([]Option(nil), opts...)
		}
	}
	return nil
}

// DialContext connects to the address on the named network, validating
// that resolved IPs are not in blocked ranges.
//
// This method implements the standard DialContextFunc signature, making it
// composable with http.Transport, grpc.Dial, and other Go networking APIs.
func (d *SafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Address might not have a port (e.g., Unix socket)
		host = address
		port = ""
	}

	// Check blocked hostnames first (fast path)
	allowedHost := d.isAllowedHost(host)
	if !allowedHost && d.isBlockedHost(host) {
		return nil, &BlockedAddressError{
			Host:   host,
			Reason: "hostname is blocked",
		}
	}

	// Try to parse as IP address directly (skip DNS for literal IPs)
	if addr, err := netip.ParseAddr(host); err == nil {
		if err := d.validateAddr(addr, allowedHost); err != nil {
			return nil, err
		}
		return d.dial(ctx, network, address)
	}

	// Resolve hostname to IP addresses
	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}

	// Validate ALL resolved addresses before attempting any connection.
	// This prevents DNS rebinding where an attacker returns one safe and one unsafe IP.
	for _, addr := range addrs {
		if err := d.validateAddr(addr, allowedHost); err != nil {
			return nil, err
		}
	}

	// All addresses are safe, connect to the first one
	var dialAddr string
	if port != "" {
		dialAddr = net.JoinHostPort(addrs[0].String(), port)
	} else {
		dialAddr = addrs[0].String()
	}

	return d.dial(ctx, network, dialAddr)
}

// Dial is a convenience method that calls DialContext with context.Background().
// Prefer DialContext for production code.
func (d *SafeDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// dial performs the actual connection using the underlying dialer.
func (d *SafeDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
	}
	return dialer.DialContext(ctx, network, address)
}

// validateAddr checks if an IP address is allowed.
func (d *SafeDialer) validateAddr(addr netip.Addr, allowedHost bool) error {
	// Unmap IPv4-mapped IPv6 addresses for consistent checking
	addr = addr.Unmap()

	if d.isAllowedAddr(addr) {
		return nil
	}

	if !d.AllowLoopback && (addr.IsLoopback() || addr.IsUnspecified()) {
		return &BlockedAddressError{
			Host:   addr.String(),
			Reason: "loopback and unspecified addresses are blocked",
		}
	}

	if !d.AllowLinkLocal && addr.IsLinkLocalUnicast() {
		return &BlockedAddressError{
			Host:   addr.String(),
			Reason: "link-local addresses are blocked (includes cloud metadata endpoints)",
		}
	}

	if !d.AllowPrivate && addr.IsPrivate() {
		if allowedHost {
			return nil
		}
		return &BlockedAddressError{
			Host:   addr.String(),
			Reason: "private network addresses are blocked",
		}
	}

	return nil
}

// isBlockedHost checks if a hostname is in the blocked list.
func (d *SafeDialer) isBlockedHost(host string) bool {
	host = strings.ToLower(host)
	for _, blocked := range d.BlockedHosts {
		blocked = strings.ToLower(blocked)
		if host == blocked || strings.HasSuffix(host, "."+blocked) {
			return true
		}
	}
	return false
}

// isAllowedHost checks if a hostname is explicitly allowed.
func (d *SafeDialer) isAllowedHost(host string) bool {
	if len(d.AllowedHosts) == 0 {
		return false
	}
	normalized := normalizeHost(host)
	if normalized == "" {
		return false
	}
	for _, entry := range d.AllowedHosts {
		entry = normalizeHost(entry)
		if entry == "" {
			continue
		}
		if entry == normalized {
			return true
		}
		if strings.HasPrefix(entry, "*.") {
			entry = strings.TrimPrefix(entry, "*")
		}
		if after, ok := strings.CutPrefix(entry, "."); ok {
			if normalized == after {
				return true
			}
			if strings.HasSuffix(normalized, entry) {
				return true
			}
		}
	}
	return false
}

func (d *SafeDialer) isAllowedAddr(addr netip.Addr) bool {
	if len(d.AllowedCIDRs) == 0 {
		return false
	}
	for _, prefix := range d.AllowedCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return host
}

// BlockedAddressError is returned when a connection is blocked due to SSRF protection.
type BlockedAddressError struct {
	Host   string
	Reason string
}

func (e *BlockedAddressError) Error() string {
	return fmt.Sprintf("connection to %s blocked: %s", e.Host, e.Reason)
}

// Is implements errors.Is for BlockedAddressError.
func (e *BlockedAddressError) Is(target error) bool {
	_, ok := target.(*BlockedAddressError)
	return ok
}

// IsBlockedAddressError returns true if err is or wraps a BlockedAddressError.
func IsBlockedAddressError(err error) bool {
	var blocked *BlockedAddressError
	return errors.As(err, &blocked)
}

// Option configures a SafeDialer. Use the With* functions to create options.
type Option func(*SafeDialer)

// WrapDialer wraps an existing DialContextFunc with SSRF protection.
// This is useful when you need to add safety to an existing dialer function.
//
//	existingDial := myTransport.DialContext
//	myTransport.DialContext = network.WrapDialer(existingDial)
func WrapDialer(dial DialContextFunc, opts ...Option) DialContextFunc {
	d := NewSafeDialer()
	for _, opt := range opts {
		opt(d)
	}
	// Store the original dial function to call after validation
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			host = address
			port = ""
		}

		// Check blocked hostnames
		allowedHost := d.isAllowedHost(host)
		if !allowedHost && d.isBlockedHost(host) {
			return nil, &BlockedAddressError{Host: host, Reason: "hostname is blocked"}
		}

		// For IP addresses, validate directly
		if addr, err := netip.ParseAddr(host); err == nil {
			if err := d.validateAddr(addr, allowedHost); err != nil {
				return nil, err
			}
			return dial(ctx, network, address)
		}

		// Resolve and validate
		resolver := d.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}

		addrs, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
		}

		for _, addr := range addrs {
			if err := d.validateAddr(addr, allowedHost); err != nil {
				return nil, err
			}
		}

		// Validation passed, use first resolved address
		var dialAddr string
		if port != "" {
			dialAddr = net.JoinHostPort(addrs[0].String(), port)
		} else {
			dialAddr = addrs[0].String()
		}

		return dial(ctx, network, dialAddr)
	}
}
