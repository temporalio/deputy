// Package network provides secure networking primitives for Deputy.
//
// # SSRF Protection
//
// The SafeDialer prevents Server-Side Request Forgery (SSRF) attacks by
// validating IP addresses at connection time, after DNS resolution. This
// eliminates DNS rebinding vulnerabilities where an attacker-controlled
// domain resolves to internal IPs.
//
// # Two-Layer Defense
//
// For complete SSRF protection, use both targets.ValidateRemoteTarget (fast
// early rejection with helpful error messages) and SafeDialer (connection-time
// validation):
//
//	// Layer 1: Early rejection with helpful error messages
//	if err := targets.ValidateRemoteTarget(userInput); err != nil {
//	    return err // User gets guidance like "use git URL or container reference"
//	}
//
//	// Layer 2: Connection-time validation (catches DNS rebinding)
//	client := &http.Client{
//	    Transport: &http.Transport{
//	        DialContext: network.NewSafeDialer().DialContext,
//	    },
//	}
//
// # Composability
//
// SafeDialer implements the standard DialContextFunc signature, making it
// composable with any Go networking code:
//
//	// HTTP clients
//	client := network.SafeClient()
//
//	// Custom http.Transport
//	transport := &http.Transport{
//	    DialContext: network.NewSafeDialer().DialContext,
//	}
//
//	// gRPC connections
//	conn, err := grpc.Dial(target,
//	    grpc.WithContextDialer(network.NewSafeDialer().DialContext),
//	)
//
//	// ConnectRPC clients
//	client := scanv1connect.NewScanServiceClient(
//	    network.SafeClient(),
//	    serverURL,
//	)
//
//	// Database drivers with custom connectors
//	dialer := network.NewSafeDialer()
//	db.SetConnector(&customConnector{dial: dialer.DialContext})
//
//	// Wrapping existing dialers
//	existingTransport := http.DefaultTransport.(*http.Transport).Clone()
//	existingTransport.DialContext = network.WrapDialer(existingTransport.DialContext)
//
// # Configuration
//
// SafeDialer blocks by default:
//   - Loopback addresses (127.x.x.x, ::1, 0.0.0.0)
//   - Private networks (10.x, 172.16-31.x, 192.168.x, fc00::/7)
//   - Link-local addresses (169.254.x.x, fe80::) including cloud metadata
//   - Known metadata hostnames (localhost, metadata.google.internal, etc.)
//
// Use options to customize:
//
//	// Allow private networks for internal service mesh
//	dialer := network.NewSafeDialerWithOptions(network.WithAllowPrivate())
//
//	// Allow explicit internal hosts and CIDRs
//	dialer := network.NewSafeDialerWithOptions(
//	    network.WithAllowedHosts(".corp.local"),
//	    network.WithAllowedCIDRs(netip.MustParsePrefix("10.0.0.0/8")),
//	)
//
//	// Allow loopback for development
//	dialer := network.NewSafeDialerWithOptions(network.WithAllowLoopback())
//
//	// Custom timeout
//	dialer := network.NewSafeDialerWithOptions(
//	    network.WithDialer(&net.Dialer{Timeout: 5 * time.Second}),
//	)
//
//	// Block additional hostnames
//	dialer := network.NewSafeDialerWithOptions(
//	    network.WithBlockedHosts("internal.company.com"),
//	)
//
// Process-wide defaults:
//
//	// Apply default options to all new SafeDialer instances
//	network.SetDefaultSafeDialerOptions(
//	    network.WithAllowedHosts(".corp.local"),
//	)
//
// # Error Handling
//
// When a connection is blocked, SafeDialer returns a BlockedAddressError:
//
//	conn, err := dialer.DialContext(ctx, "tcp", "169.254.169.254:80")
//	if network.IsBlockedAddressError(err) {
//	    // Handle SSRF attempt
//	    log.Warn("blocked SSRF attempt", "error", err)
//	}
package network
