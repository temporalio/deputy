// Package proxy implements a multi-ecosystem dependency proxy server.
// It intercepts package manager requests (e.g., npm, Go modules, PyPI, RubyGems)
// and enforces security policies before allowing downloads.
//
// The proxy acts as a middleware between the developer's machine and the
// upstream package registry. It evaluates policies against the requested
// packages and can block, warn, or modify the response based on the
// policy results.
//
// # Authentication
//
// The proxy supports JWT-based authentication via OIDC/JWKS. When enabled,
// JWT claims are validated and exposed to CEL policies via the "jwt" variable,
// enabling claim-based access control (roles, teams, custom attributes).
//
// Auth modes:
//   - disabled: No authentication (default)
//   - optional: Validate tokens if present, allow anonymous
//   - required: Reject requests without valid tokens
//
// See [AuthConfig] for configuration options.
//
// # Supported ecosystems
//
//   - Go Modules (GOPROXY)
//   - npm (Registry API)
//   - PyPI (Simple API)
//   - RubyGems (Marshal API)
package proxy
