// Package proxy implements a multi-ecosystem dependency proxy server.
// It intercepts package manager requests (e.g., npm, Go modules, PyPI, RubyGems)
// and enforces security policies before allowing downloads.
//
// The proxy acts as a middleware between the developer's machine and the
// upstream package registry. It evaluates policies against the requested
// packages and can block, warn, or modify the response based on the
// policy results.
//
// Supported ecosystems:
//   - Go Modules (GOPROXY)
//   - npm (Registry API)
//   - PyPI (Simple API)
//   - RubyGems (Marshal API)
package proxy
